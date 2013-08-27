{-# LANGUAGE OverloadedStrings          #-} 
{-# LANGUAGE RecordWildCards            #-} 
{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-} 

module Aws.Sign4.Test
    ( main
    , tests
    , testAll
    ) where

import           Aws.Sign4
import           Aws.Core
import           System.Locale
import           System.Environment
import           System.Exit
import           System.Directory
import           System.FilePath
import           Text.Printf
import           Control.Applicative
import           Control.Exception
import           Data.Char
import           Data.Time
import           Data.Attempt
import           Data.Maybe 
import           Data.Typeable 
import qualified Data.ByteString.Unsafe             as SU
import qualified Data.ByteString.Char8              as B
import qualified Data.ByteString.Lex.Integral       as LI
import qualified Data.Text                          as T
import qualified Data.CaseInsensitive               as CI
import qualified Network.HTTP.Types                 as H
import           Safe
import qualified Distribution.TestSuite             as TS



-- | Detailed-0.9/Cabal-1.14.0 test suite

tests :: [TS.Test] 
tests = map TS.impure test_list


-- map TS.impure simple_tests


-- | Something for running in ghci

testAll :: IO ()
testAll = scavenge_tests >>= mapM_ test_authz


-- | A (run)ghc entry point for running a specific test

main :: IO ()
main =
     do as <- getArgs
        rs <- case as of
                ["hdrs" ,fp] -> test_hdrs  fp
                ["creq" ,fp] -> test_creq  fp
                ["sts"  ,fp] -> test_sts   fp
                ["authz",fp] -> test_authz fp
                _            ->
                     do putStrLn "usage: aws4-test hdrs  <request-file>"
                        putStrLn "usage: aws4-test creq  <request-file>"
                        putStrLn "usage: aws4-test sts   <request-file>"
                        putStrLn "usage: aws4-test authz <request-file>"
                        exitWith $ ExitFailure 1
        case rs of
          True  -> return ()
          False -> exitWith $ ExitFailure 2



--
-- The AWS4 Test Suite
--


-- The AWS sample credentials used to calculate the AWS test vectors

aws_test_credentials :: Credentials
aws_test_credentials =
    Credentials
        { accessKeyID     = "AKIDEXAMPLE"
        , secretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        }


-- Tests to check the output at each stage auth-header generator:
--
--      test_creq   => check cannonical request    o/p  (.creq )
--      test_sts    => check string to sign        o/p  (.sts  )
--      test_creq   => check authentication header o/p  (.authz)
--
-- Prints diagnostics indicating progress & pass/failure *and* return
-- a boolean indicating whether the test passed.

test_creq, test_sts, test_authz :: FilePath -> IO Bool

test_creq  = report "CREQ  "  spCreq  s4CanonicalRequest
test_sts   = report "STS   "  spSts   s4StringToSign
test_authz = report "AUTHZ "  spAuthz s4Authz

-- test driver: takes a label, file path of answer file (as SuitePaths
-- extractor), the function to be tested and the file path of the input
-- file and runs the test, returning True iff it passes.

report :: String -> 
        (SuitePaths->FilePath) -> (Sign4->B.ByteString) -> FilePath -> IO Bool
report lab chf mk inf =
     do sp  <- check_rqf inf
        s4  <- mk_sign4 $ spReq sp
        let ans = mk s4
        chk <- B.filter (/='\r') <$> B.readFile (chf sp)
        putStr $ printf "%s:%-50s: " lab $ spName sp
        let rst = ans==chk
        case rst of
          True  -> putStrLn "matched"
          False -> 
             do putStrLn "MISMATCHED"
                putStrLn "OURS-----------------------"
                putStrLn $ B.unpack ans
                putStrLn "THEIRS---------------------"
                putStrLn $ B.unpack chk
                putStrLn "---------------------------"
                putStrLn ""
        return rst

-- Read in and parse the input HTTP request making up the Sign4 structure.

mk_sign4 :: FilePath -> IO Sign4
mk_sign4 rqf =
     do bs <- B.readFile rqf
        rq <- case parseRequest bs of
                Success rq_ -> return rq_
                Failure e   -> throw  e
        dt <- maybe (ioError $ userError dt_msg) return $ rqDate rq
      --sd   <- signatureData Timestamp aws_test_credentials
        let Request{..} = rq
        return
            Sign4
                { s4Credentials = aws_test_credentials
                , s4Date        = dt
                , s4Endpoint    = "us-east-1"
                , s4Service     = "host"
                , s4Method      = rqMethod
                , s4Path        = rqRawPathInfo
                , s4Headers     = rqRequestHeaders
                , s4Query       = rqQuery
                , s4Body        = rqBody
                , s4SgndHeaders = Nothing
                , s4CnclHeaders = Nothing
                }
  where
    dt_msg = "date missing or mangled"

-- This bundle descibes the name an individual test vector, giving the
-- name of the test, the input file and the file paths for the reference
-- outputs for each stage of the auth-header generating process.

data SuitePaths
    = SuitePaths
        { spName  :: String
        , spReq   :: FilePath
        , spCreq  :: FilePath
        , spSts   :: FilePath
        , spAuthz :: FilePath
        , spSreq  :: FilePath
        } deriving (Show)

-- Calculate the SuitePaths from the '.req' filepath of the HTTP input  

check_rqf :: FilePath -> IO SuitePaths
check_rqf rqf =
 do rbs  <- case reverse rqf of
              'q':'e':'r':'.':rbs_ -> return rbs_
              _                    -> ioError $ userError $
                                            printf "expected <foo>.req: %s" rqf
    let bse = reverse rbs
        ext = (bse ++) . ("." ++)  
    return
        SuitePaths
            { spName  = reverse $ takeWhile (/='/') rbs
            , spReq   = ext "req"
            , spCreq  = ext "creq"
            , spSts   = ext "sts"
            , spAuthz = ext "authz"
            , spSreq  = ext "sreq"
            }

--
-- Test to just print out the header and return True
--

test_hdrs :: FilePath -> IO Bool
test_hdrs fp = fmap (const True) $
     do bs <- B.readFile fp
        rq <- case parseRequest bs of
                Success rq_ -> return rq_
                Failure e   -> throw  e
        let Request{..} = rq
        fmt "Method"         rqMethod
        fmt "HttpVersion"    rqHttpVersion
        fmt "RawPathInfo"    rqRawPathInfo
        fmt "RawQueryString" rqRawQueryString
        fmt "ServerName"     rqServerName
        fmt "RequestHeaders" rqRequestHeaders
        fmt "PathInfo"       rqPathInfo
        fmt "QueryString"    rqQuery
        fmt "Date"           rqDate
        fmt "ContentLength"  rqContentLength
        fmt "Body"           rqBody
      where
        fmt :: Show a => String -> a -> IO ()
        fmt lb vl = putStr $ printf "%-30s %s\n" lb $ show vl 


--
-- parseRequest (adapted from http-proxy)
--

parseRequest :: B.ByteString -> Attempt Request
parseRequest = parse_rq . lex_headers

data Request 
    = Request
        { rqMethod         :: H.Method
        , rqHttpVersion    :: H.HttpVersion
                                    -- From the first line of the header,
                                    -- before the '?'
        , rqRawPathInfo    :: B.ByteString
                                    -- From the first line of the header,
                                    -- from the '?' onwards, but empty if none
        , rqRawQueryString :: B.ByteString
        , rqServerName     :: B.ByteString
                                    -- The request headers
        , rqRequestHeaders :: H.RequestHeaders
                                    -- Parsed path info
        , rqPathInfo       :: [T.Text]
                                    -- Parsed query string information
        , rqQuery          :: H.Query
                                    -- Just <date>, iff present
        , rqDate           :: Maybe UTCTime
                                    -- Just <content-length>, iff present
        , rqContentLength  :: Maybe Int
                                    -- Body of request
        , rqBody           :: B.ByteString
        }
    deriving (Typeable)

data InvalidRequest
    = NotEnoughLines [String]
    | BadFirstLine String
    | NonHttp
    | IncompleteHeaders
    | ConnectionClosedByPeer
    | OverLargeHeader
    deriving (Show, Typeable, Eq)
    
instance Exception InvalidRequest

-- Parse a set of header lines and body into a 'Request'

parse_rq :: ([B.ByteString],B.ByteString) -> Attempt Request
parse_rq ([]     ,_  ) = Failure $ NotEnoughLines []
parse_rq (fln:rst,bdy) = parse_first fln >>= return . parse_rq' rst bdy

parse_rq' :: [B.ByteString] -> B.ByteString -> FirstLine -> Request
parse_rq' rst bdy fl =
    Request
        { rqMethod         = mth
        , rqHttpVersion    = hvn
        , rqRawPathInfo    = rpt
        , rqRawQueryString = gets
        , rqServerName     = snm
        , rqRequestHeaders = hds
        , rqPathInfo       = H.decodePathSegments rpt
        , rqQuery          = H.parseQuery $ fudge_semi gets
        , rqDate           = dte
        , rqContentLength  = len
        , rqBody           = bdy
        }
  where
    (hst0,rpt)
        | B.null rpt0                   = ("", "/")
        | "http://" `B.isPrefixOf` rpt0 = B.break (=='/') $ B.drop 7 rpt0
        | otherwise                     = ("", rpt0)
    
    snm  = takeUntil ':' hst
    hst  = fromMaybe hst0   $  lookup "host"           hds
    dte  = parse_rfc1123   =<< lookup "date"           hds
    len  = LI.readDecimal_ <$> lookup "content-length" hds

    mth  = flMethd fl
    rpt0 = flRpath fl
    gets = flQuery fl
    hvn  = flVersn fl
        
    hds  = map parse_header rst

-- FIXME: resolve this: according to post-vanilla-query-nonunreserved
-- test vector AWS seem to treat ';' as unreserved in a URL query
-- so we fudge the reading of their example header here, but is this
-- what we should be doing anyway?

fudge_semi :: B.ByteString -> B.ByteString
fudge_semi = B.pack . concat . map fudge . B.unpack
  where
    fudge ';' = "%3B"
    fudge c   = [c]

takeUntil :: Char -> B.ByteString -> B.ByteString
takeUntil c bs =
    case B.elemIndex c bs of
       Just !idx -> SU.unsafeTake idx bs
       Nothing   -> bs
{-# INLINE takeUntil #-}

-- parse first line of HTTP header

data FirstLine
    = FirstLine 
        { flMethd :: B.ByteString
        , flRpath :: B.ByteString
        , flQuery :: B.ByteString
        , flVersn :: H.HttpVersion
        }
    deriving (Show)

parse_first :: B.ByteString -> Attempt FirstLine
parse_first bs =
    case extr $ B.split ' ' bs of
      Nothing            -> Failure $ BadFirstLine $ B.unpack bs
      Just (mth,qry,vrn) -> 
            case B.map toUpper vf == "HTTP/" of
              True  -> return $ FirstLine mth rpt qst hvn
                  where
                    (rpt,qst) = B.break (=='?') qry

                    hvn       = case vs of
                                  "1.1" -> H.http11
                                  _     -> H.http10
              False -> Failure NonHttp
          where
            (vf,vs) = B.splitAt 5 vrn
  where
    extr (mth:pth0:nxt:rst)     = Just (mth,pth0,lastDef nxt rst)
    extr _                      = Nothing

parse_header :: B.ByteString -> H.Header
parse_header bs = (CI.mk hnm, val)
  where
    val = case rln > 1 && SU.unsafeHead rst == 58 {- ':' -} of
            True  -> B.dropWhile isSpace $ SU.unsafeTail rst
            False -> rst

    rln = B.length rst

    (hnm,rst) = B.break (==':') bs

    

--test_lex :: String -> ([B.ByteString],B.ByteString)
--test_lex = lex_headers . B.pack

--
-- lex_headers
--
    
-- Split a ByteString into headers and body, batching up continuation lines

lex_headers :: B.ByteString -> ([B.ByteString],B.ByteString)
lex_headers bs = (hds,bdy)
  where
    hds       = case hls of
                  []      -> []
                  hln:rst -> grph [hln] rst

    (hls,bdy) = scan bs

-- group header lines, batching up space-starting continuation lines into
-- the header line

grph :: [B.ByteString] -> [B.ByteString] -> [B.ByteString]
grph rhs []  = reverse rhs
grph rhs lst =
    case lst of
      []      -> [hdr]
      hln:rst -> 
        case B.null hln of
          True  -> grph (hln:rhs) rst
          False -> hdr : grph [hln] rst 
  where
    hdr = B.intercalate (B.singleton '\n') $ reverse rhs

-- scan request into header lines and the body

scan :: B.ByteString -> ([B.ByteString],B.ByteString)
scan bs0 = scn [] bs0
  where
    scn rhs bs = 
        case B.null bs of
          True  -> (reverse rhs,bs)
          False -> case B.null nxt of
                     True  -> (reverse rhs,rst)
                     False -> scn (nxt:rhs) rst 
      where
        (nxt,rst) = nxt_ln bs

-- split off next line tolerantly (CRLF or LF [or indeed CR] lines handled)

nxt_ln :: B.ByteString -> (B.ByteString,B.ByteString)
nxt_ln bs0
    | B.null bs0 = (B.empty,B.empty)
    | otherwise  =
        case B.find eol bs0 of
          Nothing   -> (bs0,B.empty)
          Just '\r' -> nl_cr bs0
          _         -> nl_lf bs0
  where
    nl_cr bs =
        case B.elemIndex '\r' bs of
          Nothing -> error "nxt_ln:nl_cr: oops"
          Just n  -> (B.take n bs,tl_lf $ B.drop (n+1) bs)

    nl_lf bs =
        case B.elemIndex '\n' bs of
          Nothing -> error "nxt_ln:nl_lf: oops"
          Just n  -> (B.take n bs,        B.drop (n+1) bs)

    tl_lf bs =
        case B.uncons bs of
          Just ('\n',bs') -> bs'
          _               -> bs

    eol '\r' = True
    eol '\n' = True
    eol _    = False

parse_rfc1123 :: B.ByteString -> Maybe UTCTime
parse_rfc1123 = parseTime defaultTimeLocale "%a, %d %b %Y %T %Z" . B.unpack



--
-- Test Infrastructure
--


test_dir :: FilePath
test_dir = "aws4_testsuite"

    
newtype SimpleTest = ST { _ST :: FilePath }
    deriving (Show,Eq)

instance TS.TestOptions SimpleTest where
    name           = name_test
    options        = const []
    defaultOptions = const $ return $ TS.Options []
    check          = const $ const $ return []

instance TS.ImpureTestable SimpleTest where
    runM (ST fp) _ = 
            case fp of
              "" -> test_tests
              _  -> fmap cnv $ test_authz fp
      where
        cnv ok = if ok then TS.Pass else TS.Fail "Failed"

-- SimpleTest with empty file path => precheck (check list of tests consistent
-- with input test files in the file system)

name_test :: SimpleTest -> String
name_test (ST fp) = 
    case fp of
      "" -> "[precheck]"
      _  -> fst $ splitExtension $ snd $ splitFileName fp

-- Cabal seems to need a static list of tests: list them in board and
-- provide a test for checking it is up-to-date

test_tests :: IO TS.Result
test_tests =
 do fps <- scavenge_tests
    case map ST fps == test_list' of
      True  -> return   TS.Pass
      False -> return $ TS.Fail "list of tests out of date"

test_list, test_list' :: [SimpleTest]

test_list = ST "" : test_list'

test_list' = map ST
    [ "aws4_testsuite/get-header-key-duplicate.req"
    , "aws4_testsuite/get-unreserved.req"
    , "aws4_testsuite/get-vanilla-empty-query-key.req"
    , "aws4_testsuite/get-slash.req"
    , "aws4_testsuite/get-relative-relative.req"
    , "aws4_testsuite/get-vanilla-query-order-value.req"
    , "aws4_testsuite/get-utf8.req"
    , "aws4_testsuite/get-slash-dot-slash.req"
    , "aws4_testsuite/get-vanilla-query.req"
    , "aws4_testsuite/get-header-value-order.req"
    , "aws4_testsuite/get-vanilla-query-unreserved.req"
    , "aws4_testsuite/post-vanilla-query-space.req"
    , "aws4_testsuite/post-vanilla.req"
    , "aws4_testsuite/get-relative.req"
    , "aws4_testsuite/post-header-key-sort.req"
    , "aws4_testsuite/get-vanilla-ut8-query.req"
    , "aws4_testsuite/get-header-value-trim.req"
    , "aws4_testsuite/get-space.req"
    , "aws4_testsuite/get-slash-pointless-dot.req"
    , "aws4_testsuite/post-x-www-form-urlencoded.req"
    , "aws4_testsuite/post-header-key-case.req"
    , "aws4_testsuite/post-x-www-form-urlencoded-parameters.req"
    , "aws4_testsuite/post-vanilla-empty-query-value.req"
    , "aws4_testsuite/get-slashes.req"
    , "aws4_testsuite/get-vanilla.req"
    , "aws4_testsuite/post-header-value-case.req"
    , "aws4_testsuite/post-vanilla-query.req"
    , "aws4_testsuite/post-vanilla-query-nonunreserved.req"
    , "aws4_testsuite/get-vanilla-query-order-key.req"
    , "aws4_testsuite/get-vanilla-query-order-key-case.req"
    ]

-- Pick Out All of the .req files from aws4_testsuite/

scavenge_tests :: IO [FilePath]
scavenge_tests = map g <$> filter f <$> getDirectoryContents test_dir
  where
    f ('.':_) = False
    f fp      = snd (splitExtension fp) == ".req"

    g         = (test_dir </>)

