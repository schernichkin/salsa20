module Benchmarks where

import           Criterion.Main
import           Crypto.Cipher.Salsa20
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as BS
import           Data.Maybe
import           System.Random
import           Control.Applicative

cryptBench :: Int -> Benchmark
cryptBench rounds = bgroup ("crypt with salsa " ++ show rounds)
    [ bench "10 bytes chunk" $ whnfIO $ cryptChunk $ BS.replicate 10 0
    , bench "100 bytes chunk" $ whnfIO $ cryptChunk $ BS.replicate 100 0
    , bench "1Kb chunk" $ whnfIO $ cryptChunk $ BS.replicate 1024 0
    , bench "1Mb chunk" $ whnfIO $ cryptChunk $ BS.replicate 1048576 0
    , bench "100Mb chunk" $ whnfIO $ cryptChunk $ BS.replicate 104857600 0
    , bench "100Mb in 64 bytes chunks + concat" $ whnfIO $ cryptAll $ replicate 1638400 $ BS.replicate 64 0
    , bench "100Mb in 100 bytes chunks + concat" $ whnfIO $ cryptAll $ replicate 1048576 $ BS.replicate 100 0
    , bench "100Mb in 32Kb chunks + concat" $ whnfIO $ cryptAll $ replicate 3200 $ BS.replicate 32768 0
    ]
    where
        randomByteString :: Int -> IO ByteString
        randomByteString size = fst . BS.unfoldrN size f <$> newStdGen
            where f gen = let (x, gen) = next gen in Just (fromIntegral x, gen)

        cryptChunk :: ByteString -> IO ByteString
        cryptChunk byteString = fst . flip runCryptProcess byteString <$> cryptProcess

        cryptAll :: [ByteString] -> IO ByteString
        cryptAll xs = BS.concat . go xs <$> cryptProcess
            where
                go (x:xs) cp = let (bs', cp') = runCryptProcess cp x in bs' : go xs cp'
                go [] _ = []

        cryptProcess :: IO CryptProcess
        cryptProcess = do
            key <- fst . fromJust . readKey256 <$> randomByteString 32
            nounce <- fst . fromJust . readNounce <$> randomByteString 8
            return $ crypt (salsa rounds) key nounce 0

main :: IO ()
main = defaultMain
    [ cryptBench 8
    , cryptBench 12
    , cryptBench 20
    ]