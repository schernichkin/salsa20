{-# LANGUAGE ScopedTypeVariables #-}

module Tests where

import           Control.Monad
import           Crypto.Cipher.Salsa20                as S
import           Data.ByteString                      hiding (map)
import           Data.Maybe
import           Test.Framework                       as F
import           Test.Framework.Providers.HUnit
import           Test.Framework.Providers.QuickCheck2
import           Test.HUnit                           as U
import           Test.QuickCheck.Arbitrary

instance Arbitrary Quarter where
    arbitrary = liftM4 Quarter arbitrary arbitrary arbitrary arbitrary

instance Arbitrary S.State where
    arbitrary = liftM4 S.State arbitrary arbitrary arbitrary arbitrary

doubleroundTestGroup n f = testGroup n $ map (uncurry testCase)
        [ (n ++ " 1", f (S.State (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000))
                    @=? (S.State (Quarter 0x8186a22d 0x0040a284 0x82479210 0x06929051)
                                 (Quarter 0x08000090 0x02402200 0x00004000 0x00800000)
                                 (Quarter 0x00010200 0x20400000 0x08008104 0x00000000)
                                 (Quarter 0x20500000 0xa0000040 0x0008180a 0x612a8020)))
        , (n ++ " 2", f (S.State (Quarter 0xde501066 0x6f9eb8f7 0xe4fbbd9b 0x454e3f57)
                                 (Quarter 0xb75540d3 0x43e93a4c 0x3a6f2aa0 0x726d6b36)
                                 (Quarter 0x9243f484 0x9145d1e8 0x4fa9d247 0xdc8dee11)
                                 (Quarter 0x054bf545 0x254dd653 0xd9421b6d 0x67b276c1))
                    @=? (S.State (Quarter 0xccaaf672 0x23d960f7 0x9153e63a 0xcd9a60d0)
                                 (Quarter 0x50440492 0xf07cad19 0xae344aa0 0xdf4cfdfc)
                                 (Quarter 0xca531c29 0x8e7943db 0xac1680cd 0xd503ca00)
                                 (Quarter 0xa74b2ad6 0xbc331c5c 0x1dda24c7 0xee928277)))
        ]

salsa20TestGroup n f = testGroup n $ map (uncurry testCase)
        [ (n ++ " 0", f (S.State (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000))
                    @=? (S.State (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)
                                 (Quarter 0x00000000 0x00000000 0x00000000 0x00000000)))
        , (n ++ " 1", f (fst $ fromJust $ readState $ pack
                             [ 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136
                             , 49,237,179, 48, 1,106,178,219,175,199,166, 48, 86, 16,179,207
                             , 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113,238, 55,204, 36
                             , 79,201,235, 79, 3, 81,156, 47,203, 26,244,243, 88,118,104, 54 ])
                    @=? (fst $ fromJust $ readState $ pack
                             [ 109, 42,178,168,156,240,248,238,168,196,190,203, 26,110,170,154
                             , 29, 29,150, 26,150, 30,235,249,190,163,251, 48, 69,144, 51, 57
                             , 118, 40,152,157,180, 57, 27, 94,107, 42,236, 35, 27,111,114,114
                             , 219,236,232,135,111,155,110, 18, 24,232, 95,158,179, 19, 48,202 ]))
        , (n ++ " 2", f (fst $ fromJust $ readState $ pack
                             [ 88,118,104, 54, 79,201,235, 79, 3, 81,156, 47,203, 26,244,243
                             , 191,187,234,136,211,159, 13,115, 76, 55, 82,183, 3,117,222, 37
                             , 86, 16,179,207, 49,237,179, 48, 1,106,178,219,175,199,166, 48
                             , 238, 55,204, 36, 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113 ])
                    @=? (fst $ fromJust $ readState $ pack
                             [ 179, 19, 48,202,219,236,232,135,111,155,110, 18, 24,232, 95,158
                             , 26,110,170,154,109, 42,178,168,156,240,248,238,168,196,190,203
                             , 69,144, 51, 57, 29, 29,150, 26,150, 30,235,249,190,163,251, 48
                             , 27,111,114,114,118, 40,152,157,180, 57, 27, 94,107, 42,236, 35 ]))        ]

main :: IO ()
main = defaultMain
    [ testGroup "quarterround" $ map (uncurry testCase)
        [ ("quarterround 1", quarterround (Quarter 0x00000000 0x00000000 0x00000000 0x00000000) @=? (Quarter 0x00000000 0x00000000 0x00000000 0x00000000))
        , ("quarterround 2", quarterround (Quarter 0x00000001 0x00000000 0x00000000 0x00000000) @=? (Quarter 0x08008145 0x00000080 0x00010200 0x20500000))
        , ("quarterround 3", quarterround (Quarter 0x00000000 0x00000001 0x00000000 0x00000000) @=? (Quarter 0x88000100 0x00000001 0x00000200 0x00402000))
        , ("quarterround 4", quarterround (Quarter 0x00000000 0x00000000 0x00000001 0x00000000) @=? (Quarter 0x80040000 0x00000000 0x00000001 0x00002000))
        , ("quarterround 5", quarterround (Quarter 0x00000000 0x00000000 0x00000000 0x00000001) @=? (Quarter 0x00048044 0x00000080 0x00010000 0x20100001))
        , ("quarterround 6", quarterround (Quarter 0xe7e8c006 0xc4f9417d 0x6479b4b2 0x68c67137) @=? (Quarter 0xe876d72b 0x9361dfd5 0xf1460244 0x948541a3))
        , ("quarterround 7", quarterround (Quarter 0xd3917c5b 0x55f1c407 0x52a58a7a 0x8f887a3b) @=? (Quarter 0x3e2f308c 0xd90a8f36 0x6ab2a923 0x2883524c))
        ]
    , testGroup "rowround" $ map (uncurry testCase)
        [ ("rowround 1", rowround (S.State (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                           (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                           (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                           (Quarter 0x00000001 0x00000000 0x00000000 0x00000000))
                              @=? (S.State (Quarter 0x08008145 0x00000080 0x00010200 0x20500000)
                                           (Quarter 0x20100001 0x00048044 0x00000080 0x00010000)
                                           (Quarter 0x00000001 0x00002000 0x80040000 0x00000000)
                                           (Quarter 0x00000001 0x00000200 0x00402000 0x88000100)))
        , ("rowround 2", rowround (S.State (Quarter 0x08521bd6 0x1fe88837 0xbb2aa576 0x3aa26365)
                                           (Quarter 0xc54c6a5b 0x2fc74c2f 0x6dd39cc3 0xda0a64f6)
                                           (Quarter 0x90a2f23d 0x067f95a6 0x06b35f61 0x41e4732e)
                                           (Quarter 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a))
                              @=? (S.State (Quarter 0xa890d39d 0x65d71596 0xe9487daa 0xc8ca6a86)
                                           (Quarter 0x949d2192 0x764b7754 0xe408d9b9 0x7a41b4d1)
                                           (Quarter 0x3402e183 0x3c3af432 0x50669f96 0xd89ef0a8)
                                           (Quarter 0x0040ede5 0xb545fbce 0xd257ed4f 0x1818882d)))
        ]
    , testGroup "columnround" $ map (uncurry testCase)
        [ ("columnround 1", columnround (S.State (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                                 (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                                 (Quarter 0x00000001 0x00000000 0x00000000 0x00000000)
                                                 (Quarter 0x00000001 0x00000000 0x00000000 0x00000000))
                                    @=? (S.State (Quarter 0x10090288 0x00000000 0x00000000 0x00000000)
                                                 (Quarter 0x00000101 0x00000000 0x00000000 0x00000000)
                                                 (Quarter 0x00020401 0x00000000 0x00000000 0x00000000)
                                                 (Quarter 0x40a04001 0x00000000 0x00000000 0x00000000)))
        , ("columnround 2", columnround (S.State (Quarter 0x08521bd6 0x1fe88837 0xbb2aa576 0x3aa26365)
                                                 (Quarter 0xc54c6a5b 0x2fc74c2f 0x6dd39cc3 0xda0a64f6)
                                                 (Quarter 0x90a2f23d 0x067f95a6 0x06b35f61 0x41e4732e)
                                                 (Quarter 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a))
                                    @=? (S.State (Quarter 0x8c9d190a 0xce8e4c90 0x1ef8e9d3 0x1326a71a)
                                                 (Quarter 0x90a20123 0xead3c4f3 0x63a091a0 0xf0708d69)
                                                 (Quarter 0x789b010c 0xd195a681 0xeb7d5504 0xa774135c)
                                                 (Quarter 0x481c2027 0x53a8e4b5 0x4c1f89c5 0x3f78c9c8)))
        ]
    , doubleroundTestGroup "doubleround" doubleround
    , doubleroundTestGroup "doubleround'" doubleround'
    , salsa20TestGroup "salsa20" salsa20
    , salsa20TestGroup "salsa20'" salsa20'
    , testGroup "read/write State" $ map (uncurry testProperty)
        [ ("readState . writeState == id", \(s :: S.State) -> s == (fst $ fromJust $ readState $ writeState s))
        ]
    ]
