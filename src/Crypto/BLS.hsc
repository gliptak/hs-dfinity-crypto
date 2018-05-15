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
  , centralizedGenerateGroup
  ) where

import Control.Monad          (foldM, void)
import Data.Hashable          (Hashable)
import Data.Binary            (Binary)
import Data.ByteString.Char8  (ByteString, pack, unpack)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create)
import Data.IntMap.Strict     (IntMap, empty, insert, size, traverseWithKey)
import Data.String            (IsString)
import Data.Void              (Void)
import Data.Word              (Word8)
import Data.Hex               (hex)
import Data.List              (foldl')
import Foreign.C.Types        (CChar, CInt(..))
import Foreign.C.String       (CString)
import Foreign.Marshal.Array  (withArray)
import Foreign.Ptr            (FunPtr, Ptr, castPtr)
import GHC.Generics           (Generic)
import System.IO.Unsafe       (unsafePerformIO)

#include <bindings.dsl.h>

type MkByteString = Ptr Word8 -> IO ()

#ccall_unsafe shimInit, IO ()
#ccall_unsafe shimSign, CString -> CInt -> CString -> CInt -> MkByteString
#ccall_unsafe shimVerify, CString -> CInt -> CString -> CInt -> CString -> CInt -> IO CInt
#ccall_unsafe fromSecretNew, CString -> CInt -> MkByteString
#ccall_unsafe getPopNew, CString -> CInt -> MkByteString
#ccall_unsafe shimVerifyPop, CString -> CInt -> CString -> CInt -> IO CInt
#ccall_unsafe frmapnew, CString -> CInt -> MkByteString
#ccall_unsafe dkgNew, CInt -> IO (Ptr Void)
#ccall_unsafe dkgFree, Ptr Void -> IO ()
#ccall_unsafe dkgSecretShareNewWithId, Ptr Void -> CInt -> MkByteString
#ccall_unsafe dkgSecretShareNew, Ptr Void -> CString -> CInt -> MkByteString
#ccall_unsafe dkgPublicKeyNew, Ptr Void -> CInt -> MkByteString
#ccall_unsafe dkgPublicShareNew, Ptr Void -> Ptr CInt -> CInt -> CString -> CInt -> MkByteString
#ccall_unsafe dkgGroupPublicKeyNew, Ptr Void -> MkByteString
#ccall_unsafe signatureShareNew, CInt -> IO (Ptr Void)
#ccall_unsafe signatureShareFree, Ptr Void -> IO ()
#ccall_unsafe signatureShareAddWithId, Ptr Void -> CInt -> CString -> CInt -> IO ()
#ccall_unsafe signatureShareAdd, Ptr Void -> CString -> CInt -> CString -> CInt -> IO ()
#ccall_unsafe recoverSignatureNew, Ptr Void -> MkByteString
#ccall_unsafe secretKeyAdd, CString -> CInt -> CString -> CInt -> MkByteString
#ccall_unsafe publicKeyAdd, CString -> CInt -> CString -> CInt -> MkByteString

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

createAs :: (ByteString -> b) -> MkByteString -> IO b
createAs f act = f <$> create 64 act

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
  unsafeAsCStringLen xxx $ \ xxxPtr ->
    uncurry cfunc xxxPtr

{-# INLINE unsafeCIO1b #-}
unsafeCIO1b :: (CString -> CInt -> MkByteString)
           ->   ByteString      -> IO ByteString
unsafeCIO1b cfunc xxx = create 64 $ \ptr ->
  unsafeAsCStringLen xxx $ \ xxxPtr ->
    uncurry cfunc xxxPtr ptr

{-# INLINE unsafeCIO2 #-}
unsafeCIO2 :: (CString -> CInt -> CString -> CInt -> IO a)
           ->  ByteString      -> ByteString      -> IO a
unsafeCIO2 cfunc xxx yyy =
  unsafeAsCStringLen xxx $ \ xxxPtr ->
    unsafeAsCStringLen yyy $ \ yyyPtr ->
      uncurry (uncurry cfunc xxxPtr) yyyPtr

{-# INLINE unsafeCIO2b #-}
unsafeCIO2b :: (CString -> CInt -> CString -> CInt -> MkByteString)
           ->   ByteString      -> ByteString      -> IO ByteString
unsafeCIO2b cfunc xxx yyy = create 64 $ \ptr ->
  unsafeAsCStringLen xxx $ \ xxxPtr ->
    unsafeAsCStringLen yyy $ \ yyyPtr ->
      uncurry (uncurry cfunc xxxPtr) yyyPtr ptr

{-# INLINE unsafeCIO3 #-}
unsafeCIO3 :: (CString -> CInt -> CString -> CInt -> CString -> CInt -> IO a)
           ->  ByteString      -> ByteString      -> ByteString      -> IO a
unsafeCIO3 cfunc xxx yyy zzz =
  unsafeAsCStringLen xxx $ \ xxxPtr ->
    unsafeAsCStringLen yyy $ \ yyyPtr ->
      unsafeAsCStringLen zzz $ \ zzzPtr ->
        uncurry (uncurry (uncurry cfunc xxxPtr) yyyPtr) zzzPtr

-- |
-- Initialize a BLS cryptosystem.
initialize :: IO ()
initialize = unsafe'c'shimInit

-- |
-- Derive a BLS secret key from a random seed.
deriveSecretKey :: ByteString -> SecretKey
deriveSecretKey seed = unsafePerformIO $ SecretKey <$> unsafeCIO1b unsafe'c'frmapnew seed

-- |
-- Derive a BLS member id from a random seed.
deriveMemberId :: ByteString -> MemberId
deriveMemberId = MemberId . deriveSecretKey

-- |
-- Derive a BLS public key from a BLS secret key.
derivePublicKey :: SecretKey -> PublicKey
derivePublicKey (SecretKey sec) = unsafePerformIO $ PublicKey <$> unsafeCIO1b unsafe'c'fromSecretNew sec

-- |
-- Sign a message using a BLS secret key.
sign :: SecretKey -> ByteString -> Signature
sign (SecretKey sec) msg = unsafePerformIO $ Signature <$> unsafeCIO2b unsafe'c'shimSign sec msg

-- |
-- Verify a BLS signature on a message using a BLS public key.
verifySig :: Signature -> ByteString -> PublicKey -> Bool
verifySig (Signature sig) msg (PublicKey pub) = unsafePerformIO $ (> 0) <$> unsafeCIO3 unsafe'c'shimVerify sig pub msg

-- |
-- Prove possession of a BLS secret key.
prove :: SecretKey -> ByteString
prove (SecretKey sec) = unsafePerformIO $ unsafeCIO1b unsafe'c'getPopNew sec

-- |
-- Verify a proof of possession using a BLS public key.
verifyPop :: ByteString -> PublicKey -> Bool
verifyPop pop (PublicKey pub) = unsafePerformIO $ (> 0) <$> unsafeCIO2 unsafe'c'shimVerifyPop pop pub

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
  ptr <- unsafe'c'dkgNew t
  members <- foldM (step ptr) empty [1..n]
  publicKey <- createAs PublicKey $ unsafe'c'dkgGroupPublicKeyNew ptr
  unsafe'c'dkgFree ptr
  pure $ Group members publicKey t'
  where
  step ptr acc i = do
    secretKey <- createAs SecretKey $ unsafe'c'dkgSecretShareNewWithId ptr i
    let publicKey = derivePublicKey secretKey
    pure $ insert (fromIntegral i) (publicKey, secretKey) acc

-- |
-- Create a (verification vector, secret key contribution) pair for a single party.
newContribution :: Int -> [MemberId] -> ([PublicKey], [SecretKey])
newContribution t' cids = unsafePerformIO $ do
  let t = fromIntegral t'
  ptr <- unsafe'c'dkgNew t
  publicKeyShares <- mapM (createAs PublicKey . unsafe'c'dkgPublicKeyNew ptr) [0..(t-1)]
  secretKeyShares <- mapM (fmap SecretKey . mkShare ptr) cids
  unsafe'c'dkgFree ptr
  return (publicKeyShares, secretKeyShares)
  where
   mkShare ptr cid = unsafeCIO1b (unsafe'c'dkgSecretShareNew ptr) (getSecretKey $ getMemberId cid)

-- |
-- Create a public key from verification vector for a given id.
newPublicKeyShare :: [PublicKey] -> MemberId -> PublicKey
newPublicKeyShare vt (MemberId (SecretKey cid)) = unsafePerformIO $
  unsafeListAsCStringLen (getPublicKey <$> vt) $ \ps -> do
    let (ptrs, ptrlens) = unzip ps
    let n = fromIntegral $ length ptrlens
    withArray ptrs $ \ptr ->
      withArray ptrlens $ \ptrlen ->
        PublicKey <$> unsafeCIO1b (unsafe'c'dkgPublicShareNew (castPtr ptr) ptrlen n) cid

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recover :: IntMap Signature -> Signature
recover sigs = unsafePerformIO $ do
  ptr <- unsafe'c'signatureShareNew $ fromIntegral $ size sigs
  addSigs ptr sigs
  result <- createAs Signature $ unsafe'c'recoverSignatureNew ptr
  unsafe'c'signatureShareFree ptr
  return result
  where
    addSigs ptr ss = void $ flip traverseWithKey ss $ \ i (Signature s) ->
      unsafeCIO1 (unsafe'c'signatureShareAddWithId ptr (fromIntegral i)) s

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recoverSig :: [(MemberId, Signature)] -> Signature
recoverSig sigs = unsafePerformIO $ do
  ptr <- unsafe'c'signatureShareNew $ fromIntegral $ length sigs
  addSigs ptr sigs
  result <- createAs Signature $ unsafe'c'recoverSignatureNew ptr
  unsafe'c'signatureShareFree ptr
  return result
  where
    addSigs _   []          = return ()
    addSigs ptr ((i, x):xs) = do
      unsafeCIO2 (unsafe'c'signatureShareAdd ptr) (getSignature x) (getSecretKey $ getMemberId i)
      addSigs ptr xs

-- |
-- Recover a BLS secret key from secret key shares.
recoverSecretKey :: [SecretKey] -> SecretKey
recoverSecretKey [] = error "recoverSecretKey: input list cannot be empty"
recoverSecretKey keys = SecretKey $
  foldl' (fmap unsafePerformIO . unsafeCIO2b unsafe'c'secretKeyAdd) k ks
  where k:ks = getSecretKey <$> keys

-- |
-- Recover a BLS public key from public key shares.
recoverPublicKey :: [PublicKey] -> PublicKey
recoverPublicKey [] = error "recoverPublicKey: input list cannot be empty"
recoverPublicKey keys = PublicKey $
  foldl' (fmap unsafePerformIO . unsafeCIO2b unsafe'c'publicKeyAdd) k ks
  where k:ks = getPublicKey <$> keys

-- |
-- Generate a group public key from a given list of secret seeds.
-- More suitable for testing than for real privacy.
centralizedGenerateGroup ::
    (Show a, Monad m)
  => Int -> [a] -> m (PublicKey, [MemberId], [PublicKey], [SecretKey])
centralizedGenerateGroup t seeds = do
  let n = length seeds
  let mids = map (MemberId . deriveSecretKey . pack . show) seeds
  let (pshares, sshares) = unzip $ replicate n (newContribution t mids)
  let secrets = map (\i -> recoverSecretKey $ map (!! i) sshares) [0..n-1]
  let pubkeys = map derivePublicKey secrets
  let pubkey = recoverPublicKey $ map (!! 0) pshares
  return (pubkey, mids, pubkeys, secrets)
