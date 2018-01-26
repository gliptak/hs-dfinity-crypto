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
  , newContribution
  , newPublicKeyShare
  ) where

import Control.Monad          (foldM, void, (<=<))
import Data.Binary            (Binary)
import Data.ByteString.Char8  (ByteString)
import Data.ByteString.Unsafe (unsafePackCStringFinalizer, unsafeUseAsCStringLen)
import Data.IntMap.Strict     (IntMap, empty, insert, size, traverseWithKey)
import Data.String            (IsString)
import Data.Void              (Void)
import Data.Word              (Word8)
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
#ccall signatureShareAdd, Ptr Void -> CInt -> CString -> CInt -> IO ()
#ccall recoverSignatureNew, Ptr Void -> IO CString

-- |
-- Type of public key.
newtype PublicKey = PublicKey { getPublicKey :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

-- |
-- Type of secret key.
newtype SecretKey = SecretKey { getSecretKey :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

-- |
-- Type of signature.
newtype Signature = Signature { getSignature :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

-- |
-- In BLS, @MemberId@ is basically the same as a @SecretKey@.
newtype MemberId = MemberId { getMemberId :: SecretKey }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

-- |
-- Type of a BLS group.
data Group =
  Group
  { groupMembers   :: IntMap (PublicKey, SecretKey)
  , groupPublicKey :: PublicKey
  , groupThreshold :: Int
  } deriving (Eq, Generic, Ord, Read, Show)

instance Binary Group
instance Binary PublicKey
instance Binary SecretKey
instance Binary Signature

extract :: CString -> IO ByteString
extract str = peek ptr >>= \ len ->
  unsafePackCStringFinalizer (plusPtr ptr 1) (fromIntegral len) (free ptr)
  where ptr = castPtr str :: Ptr Word8

-- |
-- Initialize a BLS cryptosystem.
initialize :: IO ()
initialize = c'shimInit

unsafeAsCStringLen :: ByteString -> ((Ptr CChar, CInt) -> IO a) -> IO a
unsafeAsCStringLen x f = unsafeUseAsCStringLen x (f . lenToCInt)
  where
    lenToCInt (p, l) = (p, fromIntegral l)

-- |
-- Derive a BLS secret key from a random seed.
deriveSecretKey :: ByteString -> IO SecretKey
deriveSecretKey xxx =
  unsafeAsCStringLen xxx $ \ xxxPtr -> do
    result <- uncurry c'frmapnew xxxPtr
    SecretKey <$> extract result

-- |
-- Derive a BLS member id from a random seed.
deriveMemberId :: ByteString -> IO MemberId
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
sign :: SecretKey -> ByteString -> IO Signature
sign (SecretKey sec) msg =
  unsafeAsCStringLen sec $ \ secPtr ->
    unsafeAsCStringLen msg $ \ msgPtr -> do
      result <- uncurry (uncurry c'shimSign secPtr) msgPtr
      Signature <$> extract result

-- |
-- Verify a BLS signature on a message using a BLS public key.
verifySig :: Signature -> ByteString -> PublicKey -> IO Bool
verifySig (Signature sig) msg (PublicKey pub) =
  unsafeAsCStringLen sig $ \ sigPtr ->
    unsafeAsCStringLen msg $ \ msgPtr ->
      unsafeAsCStringLen pub $ \ pubPtr -> do
        result <- uncurry (uncurry (uncurry c'shimVerify sigPtr) pubPtr) msgPtr
        pure $ result > 0

-- |
-- Prove possession of a BLS secret key.
prove :: SecretKey -> IO ByteString
prove (SecretKey sec) =
  unsafeAsCStringLen sec $ \ secPtr -> do
    result <- uncurry c'getPopNew secPtr
    extract result

-- |
-- Verify a proof of possession using a BLS public key.
verifyPop :: ByteString -> PublicKey -> IO Bool
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
      uncurry (c'signatureShareAdd ptr (fromIntegral i)) sigPtr
  result <- c'recoverSignatureNew ptr
  c'signatureShareFree ptr
  Signature <$> extract result
