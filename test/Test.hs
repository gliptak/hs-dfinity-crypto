module Main where

import Control.Monad         (foldM, join, liftM, liftM2, replicateM, zipWithM)
import Data.ByteString.Char8 (ByteString, pack)
import Data.IntMap.Strict    (empty, insert, toList)
import System.Exit           (ExitCode(..), exitWith)
import System.Random.Shuffle (shuffleM)
import Test.HUnit            (Counts(..), Test(..), assertEqual, runTestTT)
import Test.QuickCheck       (Arbitrary(..), sample')

import qualified Data.Vector           as V
import qualified System.Random.MWC     as R
import qualified Crypto.Hash.SHA256    as SHA256

import Crypto.BLS

instance Arbitrary ByteString where
  arbitrary = pack <$> arbitrary

testSignVerify :: ByteString -> ByteString -> IO Test
testSignVerify seed message = do
  let secretKey = deriveSecretKey seed
  let publicKey = derivePublicKey secretKey
  let signature = sign secretKey message
  let success = verifySig signature message publicKey
  pure . TestCase $ assertEqual debug True success
  where debug = concat ["\nTest: SignVerify\nSeed: ", show seed, "\nMessage: ", show message]

testProveVerify :: ByteString -> IO Test
testProveVerify seed = do
  let secretKey = deriveSecretKey seed
  let publicKey = derivePublicKey secretKey
  let pop = prove secretKey
  let success = verifyPop pop publicKey
  pure . TestCase $ assertEqual debug True success
  where debug = concat ["\nTest: ProveVerify\nSeed: ", show seed]

testShamir :: ByteString -> IO Test
testShamir message = do
  let Group {..} = shamir 201 400
  participants <- shuffleM $ toList groupMembers
  shares <- foldM step empty participants
  let signture = recover shares
  let success = verifySig signture message groupPublicKey
  pure . TestCase $ assertEqual debug True success
  where debug = concat ["\nTest: Shamir\nMessage: ", show message]
        step accum (i, (_, secretKey)) = do
          let signature = sign secretKey message
          pure $ insert i signature accum

testRecoverSig :: Int -> Int -> IO Test
testRecoverSig n m = do
  gen       <- R.create
  mids      <- R.uniformVector gen n :: IO (V.Vector Int)
  -- mids must all be unique, QC arbitrary sometimes generates list duplicates
  let t = n * 2 `div` 3
  (gpk, mbids, npks, nsks) <- centralizedGenerateGroup t (V.toList mids)
  let miners = V.zip3 (V.fromList mbids) (V.fromList npks) (V.fromList nsks)
  let loop :: Int -> Signature -> IO Signature
      loop k msg
        | k <= 0 = return msg
        | otherwise = do
          miners' <- shuffleM $ V.toList miners
          let hash = SHA256.hash $ getSignature msg
          let sigs = map (\(nid, _, nsk) -> (nid, sign nsk hash)) miners'
          let sig  = recoverSig $ take t sigs
          let sig' = recoverSig $ drop (length sigs - t) sigs
          case (sig == sig', verifySig sig hash gpk) of
            (True, True) -> loop (k - 1) sig
            (False, _) -> error "signature mismatch"
            (_, False) -> error "signature invalid"
  result <- loop m (Signature $ pack "test")
  return $ TestCase $ assertEqual (show result) True True

random :: IO [ByteString]
random = sample' arbitrary

tests :: [IO Test]
tests =  fmap TestList . replicateM 10 . fmap TestList . join <$>
  [
    liftM (mapM testShamir) random,
    liftM (mapM testProveVerify) random,
    liftM2 (zipWithM testSignVerify) random random
  ]

singleTests :: [IO Test]
singleTests =
  [
    testRecoverSig 10 1000
  ]

main :: IO ()
main = do
  initialize
  Counts {..} <- runTestTT =<< TestList <$> sequence (tests ++ singleTests)
  exitWith $ case failures + errors of
    0 -> ExitSuccess
    _ -> ExitFailure 1
