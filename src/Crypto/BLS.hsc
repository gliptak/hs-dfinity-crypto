{-# LANGUAGE TupleSections #-}
module Crypto.BLS
  ( SecretKey(..)
  , PublicKey(..)
  , Signature(..)
  , MemberId(..)
  , Group(..)
  , initialize
  , deriveSecretKey
  , derivePublicKey
  , deriveMemberId
  , sign
  , verifySig
  , prove
  , verifyPop
  , shamir
  , recover
  , recoverSig
  , recoverSecretKey
  , recoverPublicKey
  , newContribution
  , newPublicKeyShare
  ) where

import Control.Monad          (foldM, void, (<=<))
import Data.Hashable          (Hashable)
import Data.Binary            (Binary)
import Data.ByteString.Char8  (ByteString, unpack)
import Data.ByteString.Unsafe (unsafePackCStringFinalizer, unsafeUseAsCStringLen)
import Data.IntMap.Strict     (IntMap, empty, insert, size, traverseWithKey)
import Data.String            (IsString)
import Data.Void              (Void)
import Data.Word              (Word8)
import Data.Hex               (hex)
import Data.List              (foldl')
import Foreign.C.Types        (CChar, CInt(..))
import Foreign.C.String       (CString)
import Foreign.Marshal.Array  (withArray)
import Foreign.Marshal.Alloc  (free)
import Foreign.Ptr            (FunPtr, Ptr, castPtr, plusPtr)
import Foreign.Storable       (peek)
import GHC.Generics           (Generic)
import System.IO.Unsafe       (unsafePerformIO)

#include <bindings.dsl.h>

#ccall shimInit, IO ()
#ccall shimSign, CString -> CInt -> CString -> CInt -> IO CString
#ccall shimVerify, CString -> CInt -> CString -> CInt -> CString -> CInt -> IO CInt
#ccall fromSecretNew, CString -> CInt -> IO CString
#ccall getPopNew, CString -> CInt -> IO CString
#ccall shimVerifyPop, CString -> CInt -> CString -> CInt -> IO CInt
#ccall frmapnew, CString -> CInt -> IO CString
#ccall dkgNew, CInt -> IO (Ptr Void)
#ccall dkgFree, Ptr Void -> IO ()
#ccall dkgSecretShareNewWithId, Ptr Void -> CInt -> IO CString
#ccall dkgSecretShareNew, Ptr Void -> CString -> CInt -> IO CString
#ccall dkgPublicKeyNew, Ptr Void -> CInt -> IO CString
#ccall dkgPublicShareNew, Ptr Void -> Ptr CInt -> CInt -> CString -> CInt -> IO CString
#ccall dkgGroupPublicKeyNew, Ptr Void -> IO CString
#ccall signatureShareNew, CInt -> IO (Ptr Void)
#ccall signatureShareFree, Ptr Void -> IO ()
#ccall signatureShareAddWithId, Ptr Void -> CInt -> CString -> CInt -> IO ()
#ccall signatureShareAdd, Ptr Void -> CString -> CInt -> CString -> CInt -> IO ()
#ccall recoverSignatureNew, Ptr Void -> IO CString
#ccall secretKeyAdd, CString -> CInt -> CString -> CInt -> IO CString
#ccall publicKeyAdd, CString -> CInt -> CString -> CInt -> IO CString

-- |
-- Type of public key.
newtype PublicKey = PublicKey { getPublicKey :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Hashable)

-- |
-- Type of secret key.
newtype SecretKey = SecretKey { getSecretKey :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Hashable)

-- |
-- Type of signature.
newtype Signature = Signature { getSignature :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Hashable)

-- |
-- In BLS, @MemberId@ is basically the same as a @SecretKey@.
newtype MemberId = MemberId { getMemberId :: SecretKey }
  deriving (Eq, Generic, IsString, Ord, Hashable)

instance Show PublicKey where show (PublicKey h) = unpack $ hex h
instance Show SecretKey where show (SecretKey h) = unpack $ hex h
instance Show Signature where show (Signature h) = unpack $ hex h
instance Show MemberId  where show (MemberId  h) = show h

-- |
-- Type of a BLS group.
data Group =
  Group
  { groupMembers   :: IntMap (PublicKey, SecretKey)
  , groupPublicKey :: PublicKey
  , groupThreshold :: Int
  } deriving (Eq, Generic, Ord, Show)

instance Binary Group
instance Binary PublicKey
instance Binary SecretKey
instance Binary Signature
instance Binary MemberId

extract :: CString -> IO ByteString
extract str = peek ptr >>= \ len ->
  unsafePackCStringFinalizer (plusPtr ptr 1) (fromIntegral len) (free ptr)
  where ptr = castPtr str :: Ptr Word8

extractAs :: (ByteString -> a) -> CString -> IO a
extractAs f str = f <$> extract str

unsafePerformExtract :: IO CString -> ByteString
unsafePerformExtract ioStr = unsafePerformIO $ ioStr >>= extract

unsafeAsCStringLen :: ByteString -> ((Ptr CChar, CInt) -> IO a) -> IO a
unsafeAsCStringLen x f = unsafeUseAsCStringLen x (f . lenToCInt)
  where
    lenToCInt (p, l) = (p, fromIntegral l)

unsafeListAsCStringLen :: [ByteString] -> ([(Ptr CChar, CInt)] -> IO a) -> IO a
unsafeListAsCStringLen xx f = aux (reverse xx) []
  where
    aux (x:xs) ps = unsafeAsCStringLen x (\p -> aux xs (p:ps))
    aux []     ps = f ps

{-# INLINE unsafeCIO1 #-}
unsafeCIO1 :: (CString -> CInt -> IO a)
           ->  ByteString      -> IO a
unsafeCIO1 cfunc xxx =
  unsafeAsCStringLen xxx $ \ xxxPtr -> do
    uncurry cfunc xxxPtr

{-# INLINE unsafeCIO2 #-}
unsafeCIO2 :: (CString -> CInt -> CString -> CInt -> IO a)
           ->  ByteString      -> ByteString      -> IO a
unsafeCIO2 cfunc xxx yyy =
  unsafeAsCStringLen xxx $ \ xxxPtr -> do
    unsafeAsCStringLen yyy $ \ yyyPtr -> do
      uncurry (uncurry cfunc xxxPtr) yyyPtr

{-# INLINE unsafeCIO3 #-}
unsafeCIO3 :: (CString -> CInt -> CString -> CInt -> CString -> CInt -> IO a)
           ->  ByteString      -> ByteString      -> ByteString      -> IO a
unsafeCIO3 cfunc xxx yyy zzz =
  unsafeAsCStringLen xxx $ \ xxxPtr -> do
    unsafeAsCStringLen yyy $ \ yyyPtr -> do
      unsafeAsCStringLen zzz $ \ zzzPtr -> do
        uncurry (uncurry (uncurry cfunc xxxPtr) yyyPtr) zzzPtr

-- |
-- Initialize a BLS cryptosystem.
initialize :: IO ()
initialize = c'shimInit

-- |
-- Derive a BLS secret key from a random seed.
deriveSecretKey :: ByteString -> SecretKey
deriveSecretKey seed = SecretKey $ unsafePerformExtract $ unsafeCIO1 c'frmapnew seed

-- |
-- Derive a BLS member id from a random seed.
deriveMemberId :: ByteString -> MemberId
deriveMemberId = MemberId . deriveSecretKey

-- |
-- Derive a BLS public key from a BLS secret key.
derivePublicKey :: SecretKey -> PublicKey
derivePublicKey (SecretKey sec) = PublicKey $ unsafePerformExtract $ unsafeCIO1 c'fromSecretNew sec

-- |
-- Sign a message using a BLS secret key.
sign :: SecretKey -> ByteString -> Signature
sign (SecretKey sec) msg = Signature $ unsafePerformExtract $ unsafeCIO2 c'shimSign sec msg

-- |
-- Verify a BLS signature on a message using a BLS public key.
verifySig :: Signature -> ByteString -> PublicKey -> Bool
verifySig (Signature sig) msg (PublicKey pub) = unsafePerformIO $ (> 0) <$> unsafeCIO3 c'shimVerify sig pub msg

-- |
-- Prove possession of a BLS secret key.
prove :: SecretKey -> ByteString
prove (SecretKey sec) = unsafePerformExtract $ unsafeCIO1 c'getPopNew sec

-- |
-- Verify a proof of possession using a BLS public key.
verifyPop :: ByteString -> PublicKey -> Bool
verifyPop pop (PublicKey pub) = unsafePerformIO $ (> 0) <$> unsafeCIO2 c'shimVerifyPop pop pub

-- |
-- Divide a BLS secret key into 'n' shares such that 't' shares can combine to
-- recover a group signature.
shamir
  :: Int -- ^ 't'
  -> Int -- ^ 'n'
  -> Group
shamir t n | t < 1 || n < t = error "shamir: invalid arguments"
shamir t' n' = unsafePerformIO $ do
  let t = fromIntegral t' :: CInt
      n = fromIntegral n' :: CInt
  ptr <- c'dkgNew t
  members <- foldM (step ptr) empty [1..n]
  publicKey <- c'dkgGroupPublicKeyNew ptr >>= extractAs PublicKey
  c'dkgFree ptr
  pure $ Group members publicKey t'
  where
  step ptr acc i = do
    secretKey <- c'dkgSecretShareNewWithId ptr i >>= extractAs SecretKey
    let publicKey = derivePublicKey secretKey
    pure $ insert (fromIntegral i) (publicKey, secretKey) acc

-- |
-- Create a (verification vector, secret key contribution) pair for a single party.
newContribution :: Int -> [MemberId] -> ([PublicKey], [SecretKey])
newContribution t' cids = unsafePerformIO $ do
  let t = fromIntegral t'
  ptr <- c'dkgNew t
  publicKeyShares <- mapM (extractAs PublicKey <=< c'dkgPublicKeyNew ptr) [0..(t-1)]
  secretKeyShares <- mapM (extractAs SecretKey <=< mkShare ptr) cids
  c'dkgFree ptr
  return (publicKeyShares, secretKeyShares)
  where
   mkShare ptr cid = unsafeCIO1 (c'dkgSecretShareNew ptr) (getSecretKey $ getMemberId cid)

-- |
-- Create a public key from verification vector for a given id.
newPublicKeyShare :: [PublicKey] -> MemberId -> PublicKey
newPublicKeyShare vt (MemberId (SecretKey cid)) = unsafePerformIO $
  unsafeListAsCStringLen (getPublicKey <$> vt) $ \ps -> do
    let (ptrs, ptrlens) = unzip ps
    let n = fromIntegral $ length ptrlens
    withArray ptrs $ \ptr ->
      withArray ptrlens $ \ptrlen ->
        unsafeCIO1 (c'dkgPublicShareNew (castPtr ptr) ptrlen n) cid >>=
        extractAs PublicKey

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recover :: IntMap Signature -> Signature
recover sigs = unsafePerformIO $ do
  ptr <- c'signatureShareNew $ fromIntegral $ size sigs
  addSigs ptr sigs
  result <- c'recoverSignatureNew ptr
  c'signatureShareFree ptr
  extractAs Signature result
  where
    addSigs ptr ss = void $ flip traverseWithKey ss $ \ i (Signature s) ->
      unsafeCIO1 (c'signatureShareAddWithId ptr (fromIntegral i)) s

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recoverSig :: [(MemberId, Signature)] -> Signature
recoverSig sigs = unsafePerformIO $ do
  ptr <- c'signatureShareNew $ fromIntegral $ length sigs
  addSigs ptr sigs
  result <- c'recoverSignatureNew ptr
  c'signatureShareFree ptr
  extractAs Signature result
  where
    addSigs _   []          = return ()
    addSigs ptr ((i, x):xs) = do
      unsafeCIO2 (c'signatureShareAdd ptr) (getSignature x) (getSecretKey $ getMemberId i)
      addSigs ptr xs

-- fmap a function of 2 arguments, aka "boob operator"
(.:) :: (b -> c) -> (a1 -> a2 -> b) -> a1 -> a2 -> c
(.:) = (.) . (.)

-- |
-- Recover a BLS secret key from secret key shares.
recoverSecretKey :: [SecretKey] -> SecretKey
recoverSecretKey [] = error "recoverSecretKey: input list cannot be empty"
recoverSecretKey keys = SecretKey $
  foldl' (unsafePerformExtract .: unsafeCIO2 c'secretKeyAdd) k ks
  where k:ks = getSecretKey <$> keys

-- |
-- Recover a BLS public key from public key shares.
recoverPublicKey :: [PublicKey] -> PublicKey
recoverPublicKey [] = error "recoverPublicKey: input list cannot be empty"
recoverPublicKey keys = PublicKey $
  foldl' (unsafePerformExtract .: unsafeCIO2 c'publicKeyAdd) k ks
  where k:ks = getPublicKey <$> keys
