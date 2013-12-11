-- | Salsa20 Haskell implementation 
-- Specification: http://cr.yp.to/snuffle/spec.pdf
-- Little-endian only

module Crypto.Cipher.Salsa20 
    ( module LE 
    ) where

import Crypto.Cipher.Salsa20.LE as LE
