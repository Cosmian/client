use cosmian_findex::{ADDRESS_LENGTH, Address, MemoryADT};
use tracing::{info, trace};

use super::KmsEncryptionLayer;
use crate::ClientError;

impl<
    const WORD_LENGTH: usize,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> MemoryADT for KmsEncryptionLayer<WORD_LENGTH, Memory>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Error = ClientError;
    type Word = [u8; WORD_LENGTH];

    #[allow(clippy::print_stdout)]
    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        info!("guarded_write: guard: {:?}", guard);
        println!("guarded_write: guard: {guard:?}");
        let (address, optional_word) = guard;

        // Split bindings into two vectors
        let (mut bindings, mut bindings_words): (Vec<_>, Vec<_>) = bindings.into_iter().unzip();
        trace!("guarded_write: bindings_addresses: {bindings:?}");
        trace!("guarded_write: bindings_words: {bindings_words:?}");

        // Compute HMAC of all addresses together (including the guard address)
        bindings.push(address); // size: n+1
        let mut tokens = self.hmac(bindings).await?;
        trace!("guarded_write: tokens: {tokens:?}");

        // Put apart the last token
        let token = tokens
            .pop()
            .ok_or_else(|| ClientError::Default("No token found".to_owned()))?;

        let (ciphertexts_and_tokens, old) = if let Some(word) = optional_word {
            // Zip words and tokens
            bindings_words.push(word); // size: n+1
            tokens.push(token); // size: n+1

            // Bulk Encrypt
            let mut ciphertexts = self.encrypt(&bindings_words, &tokens).await?;
            trace!("guarded_write: ciphertexts: {ciphertexts:?}");

            // Pop the old value
            let old = ciphertexts
                .pop()
                .ok_or_else(|| ClientError::Default("No ciphertext found".to_owned()))?;

            // Zip ciphertexts and tokens
            (ciphertexts.into_iter().zip(tokens), Some(old))
        } else {
            // Bulk Encrypt
            let ciphertexts = self.encrypt(&bindings_words, &tokens).await?;
            trace!("guarded_write: ciphertexts: {ciphertexts:?}");

            // Zip ciphertexts and tokens
            (ciphertexts.into_iter().zip(tokens), None)
        };

        //
        // Send bindings to server
        let cur = self
            .mem
            .guarded_write(
                (token, old),
                ciphertexts_and_tokens
                    .into_iter()
                    .map(|(w, a)| (a, w))
                    .collect(),
            )
            .await
            .map_err(|e| ClientError::Default(format!("Memory error: {e}")))?;

        //
        // Decrypt the current value (if any)
        let res = match cur {
            Some(ctx) => Some(
                *self
                    .decrypt(&[ctx], &[token])
                    .await?
                    .first()
                    .ok_or_else(|| ClientError::Default("No plaintext found".to_owned()))?,
            ),
            None => None,
        };
        trace!("guarded_write: res: {res:?}");

        Ok(res)
    }

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        trace!("batch_read: Addresses: {:?}", addresses);

        // Compute HMAC of all addresses
        let tokens = self.hmac(addresses).await?;
        trace!("batch_read: tokens: {:?}", tokens);

        // Read encrypted values server-side
        let ciphertexts = self
            .mem
            .batch_read(tokens.clone())
            .await
            .map_err(|e| ClientError::Default(format!("Memory error: {e}")))?;
        trace!("batch_read: ciphertexts: {ciphertexts:?}");

        // Track the positions of None values and bulk ciphertexts and tokens
        let (stripped_ciphertexts, stripped_tokens, none_positions): (Vec<_>, Vec<_>, Vec<_>) =
            ciphertexts
                .into_iter()
                .zip(tokens.into_iter())
                .enumerate()
                .fold(
                    (vec![], vec![], vec![]),
                    |(mut ctxs, mut ts, mut ns), (i, (c, t))| {
                        match c {
                            Some(cipher) => {
                                ctxs.push(cipher);
                                ts.push(t);
                            }
                            None => ns.push(i),
                        }
                        (ctxs, ts, ns)
                    },
                );

        // Recover plaintext-words
        let words = self
            .decrypt(&stripped_ciphertexts, &stripped_tokens)
            .await?;
        trace!("batch_read: words: {:?}", words);

        let mut res = words.into_iter().map(Some).collect::<Vec<_>>();
        for i in none_positions {
            res.insert(i, None);
        }
        trace!("batch_read: res: {:?}", res);

        Ok(res)
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn, clippy::indexing_slicing)]
mod tests {
    use std::{env, fmt::Debug, sync::Arc};

    use cosmian_crypto_core::{
        CsRng, Sampling,
        reexport::rand_core::{RngCore, SeedableRng},
    };
    use cosmian_findex::{
        RedisMemory,
        test_utils::{gen_seed, test_single_write_and_read, test_wrong_guard},
    };
    use cosmian_findex_structs::CUSTOM_WORD_LENGTH;
    use cosmian_kms_client::{
        KmsClient, KmsClientConfig,
        kmip_2_1::{
            extra::tagging::EMPTY_TAGS, kmip_types::CryptographicAlgorithm,
            requests::symmetric_key_create_request,
        },
    };
    use cosmian_logger::log_init;
    use test_kms_server::start_default_test_kms_server;
    use tokio::task;
    use tracing::info;

    use super::*;
    use crate::ClientResult;

    fn get_redis_url(redis_url_var_env: &str) -> String {
        env::var(redis_url_var_env).unwrap_or_else(|_| "redis://localhost:6379".to_owned())
    }

    #[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
    async fn create_test_layer<const WORD_LENGTH: usize>(
        kms_config: KmsClientConfig,
    ) -> ClientResult<
        KmsEncryptionLayer<WORD_LENGTH, RedisMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>>,
    > {
        let memory = RedisMemory::connect(&get_redis_url("REDIS_URL"))
            .await
            .unwrap();
        // InMemory::default();
        let kms_client = KmsClient::new_with_config(kms_config)?;
        info!("KMS client created");
        let k_p = kms_client
            .create(symmetric_key_create_request(
                None,
                256,
                CryptographicAlgorithm::SHAKE256,
                EMPTY_TAGS,
                false,
                None,
            )?)
            .await?
            .unique_identifier
            .to_string();
        info!("KMS key created");
        let k_xts = kms_client
            .create(symmetric_key_create_request(
                None,
                512,
                CryptographicAlgorithm::AES,
                EMPTY_TAGS,
                false,
                None,
            )?)
            .await?
            .unique_identifier
            .to_string();
        info!("KMS key created part 2");
        Ok(KmsEncryptionLayer::<WORD_LENGTH, _>::new(
            kms_client, k_p, k_xts, memory,
        ))
    }

    #[tokio::test]
    #[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
    async fn test_adt_encrypt_decrypt() -> ClientResult<()> {
        let mut rng = CsRng::from_entropy();
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = [1; CUSTOM_WORD_LENGTH];

        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let layer = Arc::new(layer);
        let mut handles = vec![];

        handles.push(task::spawn(async move {
            for _ in 0..1_000 {
                let ctx = layer.encrypt(&[ptx], &[tok]).await?.remove(0);
                let res = layer.decrypt(&[ctx], &[tok]).await?.remove(0);
                assert_eq!(ptx, res);
                assert_eq!(ptx.len(), res.len());
            }
            Ok::<(), ClientError>(())
        }));

        for handle in handles {
            handle.await.unwrap()?;
        }
        Ok(())
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[tokio::test]
    async fn test_single_vector_push() -> ClientResult<()> {
        log_init(None);
        let mut rng = CsRng::from_entropy();

        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            layer
                .guarded_write((header_addr, None), vec![(
                    header_addr,
                    [2; CUSTOM_WORD_LENGTH]
                ),])
                .await?,
            None
        );

        assert_eq!(
            vec![Some([2; CUSTOM_WORD_LENGTH])],
            layer.batch_read(vec![header_addr,]).await?
        );
        Ok(())
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[tokio::test]
    async fn test_twice_vector_push() -> ClientResult<()> {
        log_init(None);
        let mut rng = CsRng::from_entropy();
        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            layer
                .guarded_write((header_addr, None), vec![
                    (header_addr, [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_1, [1; CUSTOM_WORD_LENGTH]),
                ])
                .await?,
            None
        );

        assert_eq!(
            vec![Some([2; CUSTOM_WORD_LENGTH]), Some([1; CUSTOM_WORD_LENGTH])],
            layer.batch_read(vec![header_addr, val_addr_1,]).await?
        );
        Ok(())
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[tokio::test]
    async fn test_vector_push() -> ClientResult<()> {
        log_init(None);
        let mut rng = CsRng::from_entropy();
        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_2 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_3 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_4 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            layer
                .guarded_write((header_addr, None), vec![
                    (header_addr, [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_1, [1; CUSTOM_WORD_LENGTH]),
                    (val_addr_2, [1; CUSTOM_WORD_LENGTH])
                ])
                .await?,
            None
        );

        assert_eq!(
            layer
                .guarded_write((header_addr, None), vec![
                    (header_addr, [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_1, [3; CUSTOM_WORD_LENGTH]),
                    (val_addr_2, [3; CUSTOM_WORD_LENGTH])
                ])
                .await?,
            Some([2; CUSTOM_WORD_LENGTH])
        );

        assert_eq!(
            layer
                .guarded_write((header_addr, Some([2; CUSTOM_WORD_LENGTH])), vec![
                    (header_addr, [4; CUSTOM_WORD_LENGTH]),
                    (val_addr_3, [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_4, [2; CUSTOM_WORD_LENGTH])
                ])
                .await?,
            Some([2; CUSTOM_WORD_LENGTH])
        );

        assert_eq!(
            vec![
                Some([4; CUSTOM_WORD_LENGTH]),
                Some([1; CUSTOM_WORD_LENGTH]),
                Some([1; CUSTOM_WORD_LENGTH]),
                Some([2; CUSTOM_WORD_LENGTH]),
                Some([2; CUSTOM_WORD_LENGTH])
            ],
            layer
                .batch_read(vec![
                    header_addr,
                    val_addr_1,
                    val_addr_2,
                    val_addr_3,
                    val_addr_4
                ])
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_sequential_read_write() -> ClientResult<()> {
        log_init(None);
        let ctx = start_default_test_kms_server().await;
        let memory = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        test_single_write_and_read::<CUSTOM_WORD_LENGTH, _>(&memory, gen_seed()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_sequential_wrong_guard() -> ClientResult<()> {
        let ctx = start_default_test_kms_server().await;
        let memory = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;
        test_wrong_guard::<CUSTOM_WORD_LENGTH, _>(&memory, gen_seed()).await;
        Ok(())
    }

    fn gen_bytes<const BYTES_LENGTH: usize>(rng: &mut impl RngCore) -> [u8; BYTES_LENGTH] {
        let mut bytes = [0; BYTES_LENGTH];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn u128_to_array<const WORD_LENGTH: usize>(u: u128) -> [u8; WORD_LENGTH] {
        let mut bytes = [0_u8; WORD_LENGTH];
        bytes[..16].copy_from_slice(&u.to_be_bytes());
        bytes
    }

    fn word_to_array<const WORD_LENGTH: usize>(
        word: [u8; WORD_LENGTH],
    ) -> Result<u128, &'static str> {
        if WORD_LENGTH < 16 {
            return Err("WORD_LENGTH must be at least 16 bytes");
        }
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&word[..16]);
        Ok(u128::from_be_bytes(bytes))
    }

    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::as_conversions)]
    async fn test_guarded_write_concurrent_debugger<const WORD_LENGTH: usize, Memory>(
        memory: &Memory,
        seed: [u8; 32],
        n_threads: Option<usize>,
    ) where
        Memory: 'static + Send + Sync + MemoryADT + Clone,
        Memory::Address: Send + From<[u8; ADDRESS_LENGTH]>,
        Memory::Word:
            Send + Debug + PartialEq + From<[u8; WORD_LENGTH]> + Into<[u8; WORD_LENGTH]> + Clone,
        Memory::Error: Send + std::error::Error,
    {
        const M: usize = 10; // number of increments per worker
        // A worker increment N times the counter m[a].
        async fn worker<const WORD_LENGTH: usize, Memory>(
            m: Memory,
            a: [u8; ADDRESS_LENGTH],
        ) -> Result<(), Memory::Error>
        where
            Memory: 'static + Send + Sync + MemoryADT + Clone,
            Memory::Address: Send + From<[u8; ADDRESS_LENGTH]>,
            Memory::Word: Send
                + Debug
                + PartialEq
                + From<[u8; WORD_LENGTH]>
                + Into<[u8; WORD_LENGTH]>
                + Clone,
        {
            let mut cnt = 0_u128;
            for _ in 0..M {
                let mut backoff_ms = 1; // Start with 1ms backoff
                let mut attempts = 0;

                loop {
                    let guard = if 0 == cnt {
                        None
                    } else {
                        Some(Memory::Word::from(u128_to_array(cnt)))
                    };

                    let new_cnt = cnt + 1;
                    let cur_cnt = m
                        .guarded_write((a.into(), guard), vec![(
                            a.into(),
                            Memory::Word::from(u128_to_array(new_cnt)),
                        )])
                        .await?
                        .map(|w| word_to_array(w.into()).unwrap())
                        .unwrap_or_default();

                    if cnt == cur_cnt {
                        cnt = new_cnt;
                        break;
                    }

                    // Contention detected - apply backoff with jitter
                    attempts += 1;
                    cnt = cur_cnt;

                    if attempts > 1 {
                        // Apply exponential backoff with no random jitter
                        let sleep_time = std::time::Duration::from_millis(backoff_ms);
                        tokio::time::sleep(sleep_time).await;

                        // Exponential increase with cap at 100ms
                        backoff_ms = std::cmp::min(backoff_ms * 2, 100);
                    }
                }
            }
            Ok(())
        }

        let n: usize = n_threads.unwrap_or(100); // number of workers
        let mut rng = CsRng::from_seed(seed);
        let a = gen_bytes(&mut rng);

        let handles = (0..n)
            .map(|_| {
                let m = memory.clone();
                tokio::spawn(worker(m, a))
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        let final_count = memory.batch_read(vec![a.into()]).await.unwrap()[0]
            .clone()
            .expect("Counter should exist");

        assert_eq!(
            word_to_array(final_count.clone().into()).unwrap(),
            (n * M) as u128,
            "test_guarded_write_concurrent failed. Expected the counter to be at {:?}, found \
             {:?}.\nDebug seed : {:?}.",
            (n * M) as u128,
            word_to_array(final_count.into()).unwrap(),
            seed
        );
    }

    // #[ignore = "stack overflow"]
    #[allow(clippy::print_stdout)]
    #[tokio::test]
    async fn test_concurrent_read_write() -> ClientResult<()> {
        log_init(None);
        info!("start the test ... trying to start the server");
        println!("start the test ... trying to start the server");
        // let ctx = start_default_test_kms_server().await;
        let ctx = Box::new(start_default_test_kms_server().await);

        info!("the kms server is started");
        println!("the kms server is started");
        let memory = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;
        info!("the kms layer is created");
        println!("the kms layer is created");
        unsafe { backtrace_on_stack_overflow::enable() };
        test_guarded_write_concurrent_debugger::<CUSTOM_WORD_LENGTH, _>(
            &memory,
            gen_seed(),
            Some(20),
        )
        .await;
        info!("the test is done");
        println!("the test is done");
        Ok(())
    }
}
