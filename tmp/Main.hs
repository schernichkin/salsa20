module Main where

import           Crypto.Cipher.Salsa20
import           Data.Bits
import           Data.ByteString       as BS hiding (concatMap, reverse)
import           Data.ByteString.Lazy  as LBS hiding (concatMap, reverse)
import           Data.Char
import           Data.Maybe
import           Foreign.Storable
import           Numeric
-- import           Test.Framework  as F
import           Data.Int
import           Test.HUnit

readHexString :: (Storable a) => String -> a
readHexString = fst . fromJust . readBinary . hexToByteString

hexToByteString :: String -> BS.ByteString
hexToByteString = BS.unfoldr convert
    where
        convert (a:b:xs) = Just $ (fromIntegral $ (digitToInt a) `shiftL` 4 + (digitToInt b), xs)
        convert (a:_) = error "Bytestring literal length should be even."
        convert [] = Nothing

writeHexString :: (Storable a) => a -> String
writeHexString = concatMap convert . BS.unpack . writeBinary
    where
        convert b = showHex b (if b < 0x0F then "0" else "")

keystreamToBytestring :: Keystream -> LBS.ByteString
keystreamToBytestring = fromChunks . go
    where
        go (Keystream block keystream) = writeBinary block : go keystream

assertStreamEquals :: Keystream -> (Int64, Int64) -> String -> Assertion
assertStreamEquals keystream (from, to) excepted = actual @=? fromChunks [hexToByteString excepted]
    where
        actual = LBS.take (to - from + 1) $ LBS.drop from $ keystreamToBytestring keystream

a = [10,20,30,40]

k s = "0x" ++ (concatMap (\c -> showHex c "") $ reverse s)

t :: BS.ByteString
t = read "01"

main = do
    let cs = keystream (expand128 salsa20) (readHexString "80000000000000000000000000000000") (readHexString "0000000000000000") (SeqNum 0)
    let a = assertStreamEquals cs (0, 63) $  "4DFA5E481DA23EA09A31022050859936"
                                          ++ "DA52FCEE218005164F267CB65F5CFD7F"
                                          ++ "2B4F97E0FF16924A52DF269515110A07"
                                          ++ "F9E460BC65EF95DA58F740B7D1DBB0AA"
    runTestTT $ test a
    -- print $ t
    print $ k [101, 120, 112, 97]
    print $ k [110, 100, 32, 49]
    print $ k [54, 45, 98, 121]
    print $ k [116, 101, 32, 107]
    return ()
