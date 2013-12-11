module Main where

import Numeric

a = [10,20,30,40]

k s = "0x" ++ (concatMap (\c -> showHex c "") $ reverse s)

main = do
    print $ k [101, 120, 112, 97]
    print $ k [110, 100, 32, 49]
    print $ k [54, 45, 98, 121]
    print $ k [116, 101, 32, 107]
    return ()