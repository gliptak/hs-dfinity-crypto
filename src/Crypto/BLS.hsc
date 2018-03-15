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
import Data.ByteString.Char8  (unpack)
import Data.ByteString.Short  (ShortByteString, toShort, fromShort)
import Data.ByteString.Unsafe (unsafePackCStringFinalizer, unsafeUseAsCStringLen)
import Data.IntMap.Strict     (IntMap, empty, insert, size, traverseWithKey)
import Data.String            (IsString)
import Data.Void              (Void)
import Data.Word              (Word8)
import Data.Hex               (hex)
import Foreign.C.Types        (CChar, CInt(..))
import Foreign.C.String       (CString)
import Foreign.Marshal.Array  (withArray)
import Foreign.Marshal.Alloc  (free)
import Foreign.Ptr            (FunPtr, Ptr, castPtr, plusPtr)
import Foreign.Storable       (peek)
import GHC.Generics           (Generic)

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
newtype PublicKey = PublicKey { getPublicKey :: ShortByteString }
  deriving (Eq, Generic, IsString, Ord, Hashable)

-- |
-- Type of secret key.
newtype SecretKey = SecretKey { getSecretKey :: ShortByteString }
  deriving (Eq, Generic, IsString, Ord, Hashable)

-- |
-- Type of signature.
newtype Signature = Signature { getSignature :: ShortByteString }
  deriving (Eq, Generic, IsString, Ord, Hashable)

-- |
-- In BLS, @MemberId@ is basically the same as a @SecretKey@.
newtype MemberId = MemberId { getMemberId :: SecretKey }
  deriving (Eq, Generic, IsString, Ord, Hashable)

instance Show PublicKey where show (PublicKey h) = unpack $ hex $ fromShort h
instance Show SecretKey where show (SecretKey h) = unpack $ hex $ fromShort h
instance Show Signature where show (Signature h) = unpack $ hex $ fromShort h
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

extract :: CString -> IO ShortByteString
extract str = peek ptr >>= \ len -> toShort <$>
  unsafePackCStringFinalizer (plusPtr ptr 1) (fromIntegral len) (free ptr)
  where ptr = castPtr str :: Ptr Word8

-- |
-- Initialize a BLS cryptosystem.
initialize :: IO ()
initialize = c'shimInit

unsafeAsCStringLen :: ShortByteString -> ((Ptr CChar, CInt) -> IO a) -> IO a
unsafeAsCStringLen x f = unsafeUseAsCStringLen (fromShort x) (f . lenToCInt)
  where
    lenToCInt (p, l) = (p, fromIntegral l)

-- |
-- Derive a BLS secret key from a random seed.
deriveSecretKey :: ShortByteString -> IO SecretKey
deriveSecretKey xxx =
  unsafeAsCStringLen xxx $ \ xxxPtr -> do
    result <- uncurry c'frmapnew xxxPtr
    SecretKey <$> extract result

-- |
-- Derive a BLS member id from a random seed.
deriveMemberId :: ShortByteString -> IO MemberId
deriveMemberId = fmap MemberId . deriveSecretKey

-- |
-- Derive a BLS public key from a BLS secret key.
derivePublicKey :: SecretKey -> IO PublicKey
derivePublicKey (SecretKey sec) =
  unsafeAsCStringLen sec $ \ secPtr -> do
    result <- uncurry c'fromSecretNew secPtr
    PublicKey <$> extract result

-- |
-- Sign a message using a BLS secret key.
sign :: SecretKey -> ShortByteString -> IO Signature
sign (SecretKey sec) msg =
  unsafeAsCStringLen sec $ \ secPtr ->
    unsafeAsCStringLen msg $ \ msgPtr -> do
      result <- uncurry (uncurry c'shimSign secPtr) msgPtr
      Signature <$> extract result

-- |
-- Verify a BLS signature on a message using a BLS public key.
verifySig :: Signature -> ShortByteString -> PublicKey -> IO Bool
verifySig (Signature sig) msg (PublicKey pub) =
  unsafeAsCStringLen sig $ \ sigPtr ->
    unsafeAsCStringLen msg $ \ msgPtr ->
      unsafeAsCStringLen pub $ \ pubPtr -> do
        result <- uncurry (uncurry (uncurry c'shimVerify sigPtr) pubPtr) msgPtr
        pure $ result > 0

-- |
-- Prove possession of a BLS secret key.
prove :: SecretKey -> IO ShortByteString
prove (SecretKey sec) =
  unsafeAsCStringLen sec $ \ secPtr -> do
    result <- uncurry c'getPopNew secPtr
    extract result

-- |
-- Verify a proof of possession using a BLS public key.
verifyPop :: ShortByteString -> PublicKey -> IO Bool
verifyPop pop (PublicKey pub) =
  unsafeAsCStringLen pop $ \ popPtr ->
    unsafeAsCStringLen pub $ \ pubPtr -> do
      result <- uncurry (uncurry c'shimVerifyPop popPtr) pubPtr
      pure $ result > 0

-- |
-- Divide a BLS secret key into 'n' shares such that 't' shares can combine to
-- recover a group signature.
shamir
  :: Int -- ^ 't'
  -> Int -- ^ 'n'
  -> IO Group
shamir t n | t < 1 || n < t = error "shamir: invalid arguments"
shamir t' n' = do
  let t = fromIntegral t' :: CInt
      n = fromIntegral n' :: CInt
  ptr <- c'dkgNew t
  members <- foldM (step ptr) empty [1..n]
  result <- c'dkgGroupPublicKeyNew ptr
  publicKey <- PublicKey <$> extract result
  c'dkgFree ptr
  pure $ Group members publicKey t'
  where
  step ptr acc i = do
    result <- c'dkgSecretShareNewWithId ptr i
    secretKey <- SecretKey <$> extract result
    publicKey <- derivePublicKey secretKey
    pure $ insert (fromIntegral i) (publicKey, secretKey) acc

-- |
-- Create a (verification vector, secret key contribution) pair for a single party.
newContribution :: Int -> [MemberId] -> IO ([PublicKey], [SecretKey])
newContribution t' cids = do
  let t = fromIntegral t'
  ptr <- c'dkgNew t
  publicKeyShares <- mapM (fmap PublicKey . extract <=< c'dkgPublicKeyNew ptr) [0..(t-1)]
  secretKeyShares <- mapM (mkShare ptr) cids
  c'dkgFree ptr
  return (publicKeyShares, secretKeyShares)
  where
   mkShare ptr cid = unsafeAsCStringLen (getSecretKey $ getMemberId cid) $
           (fmap SecretKey . extract <=< uncurry (c'dkgSecretShareNew ptr))

-- |
-- Create a public key from verification vector for a given id.
newPublicKeyShare :: [PublicKey] -> MemberId -> IO PublicKey
newPublicKeyShare vt cid = aux (reverse vt) []
  where
    n = fromIntegral $ length vt
    aux (k:ks) ps = unsafeAsCStringLen (getPublicKey k) (\p -> aux ks (p:ps))
    aux [] ps = do
      let (ptrs, ptrlens) = unzip ps
      withArray ptrs $ \ptr ->
        withArray ptrlens $ \ptrlen ->
          unsafeAsCStringLen (getSecretKey $ getMemberId cid) $ \cPtr -> do
            uncurry (c'dkgPublicShareNew (castPtr ptr) ptrlen n) cPtr >>=
              extract >>= return . PublicKey

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recover :: IntMap Signature -> IO Signature
recover sigs = do
  ptr <- c'signatureShareNew $ fromIntegral $ size sigs
  void $ flip traverseWithKey sigs $ \ i (Signature sig) ->
    unsafeAsCStringLen sig $ \ sigPtr ->
      uncurry (c'signatureShareAddWithId ptr (fromIntegral i)) sigPtr
  result <- c'recoverSignatureNew ptr
  c'signatureShareFree ptr
  Signature <$> extract result

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recoverSig :: [(MemberId, Signature)] -> IO Signature
recoverSig sigs = do
  ptr <- c'signatureShareNew $ fromIntegral $ length sigs
  addSigs ptr sigs
  result <- c'recoverSignatureNew ptr
  c'signatureShareFree ptr
  Signature <$> extract result
  where
    addSigs _   []          = return ()
    addSigs ptr ((i, x):xs) = do
      unsafeAsCStringLen (getSecretKey $ getMemberId i) $
        unsafeAsCStringLen (getSignature x) . uncurry . uncurry (c'signatureShareAdd ptr)
      addSigs ptr xs

-- |
-- Recover a BLS secret key from secret key shares.
recoverSecretKey :: [SecretKey] -> IO SecretKey
recoverSecretKey [] = error "recoverSecretKey: input list cannot be empty"
recoverSecretKey (key:keys) = addSecretKeys keys (getSecretKey key)
  where
    addSecretKeys (x:xs) k = (unsafeAsCStringLen k $
      unsafeAsCStringLen (getSecretKey x) . uncurry . uncurry c'secretKeyAdd) >>=
      extract >>= addSecretKeys xs
    addSecretKeys []     k = return (SecretKey k)

-- |
-- Recover a BLS public key from public key shares.
recoverPublicKey :: [PublicKey] -> IO PublicKey
recoverPublicKey [] = error "recoverPublicKey: input list cannot be empty"
recoverPublicKey (key:keys) = addPublicKeys keys (getPublicKey key)
  where
    addPublicKeys (x:xs) k = (unsafeAsCStringLen k $
      unsafeAsCStringLen (getPublicKey x) . uncurry . uncurry c'publicKeyAdd) >>=
      extract >>= addPublicKeys xs
    addPublicKeys  []    k = return (PublicKey k)
