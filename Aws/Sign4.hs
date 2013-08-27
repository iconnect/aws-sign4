{-# LANGUAGE OverloadedStrings          #-} 
{-# LANGUAGE RecordWildCards            #-} 
{-# LANGUAGE DeriveDataTypeable         #-} 

module Aws.Sign4
    ( Sign4(..)
    , s4Authz
    , s4StringToSign
    , s4CanonicalRequest
    , iso8601BasicUtcDate
    ) where

import           Aws.Core
import           Crypto.Hash
import           Data.Byteable
import qualified Data.ByteString          as B
import           Data.ByteString.Char8    ({- IsString -})
import qualified Data.ByteString.Char8          as BC
import qualified Data.CaseInsensitive           as CI
import           Data.Char
import           Data.List
import           Data.Monoid
import           Data.Time
import           Data.Typeable
import qualified Blaze.ByteString.Builder       as Bl
import qualified Blaze.ByteString.Builder.Char8 as Bl8
import qualified Network.HTTP.Types             as H
import           Network.HTTP.Types.URI
import           System.Locale
import           Text.Printf
import           Safe


-- | Signature v4 generator parameters

data Sign4
    = Sign4
        { s4Credentials :: Credentials          -- ^ AWS credentials used to sign the request
        , s4Date        :: UTCTime              -- ^ date/time stamp for request
        , s4Endpoint    :: B.ByteString         -- ^ service id: "ets" for Elastic Transcode
        , s4Service     :: B.ByteString         -- ^ service id: ets => Elastic Transcode
        , s4Method      :: H.Method             -- ^ HTTP request method
        , s4Path        :: B.ByteString         -- ^ URI path component (excluding host & query)
        , s4Headers     :: H.RequestHeaders     -- ^ The request headers
        , s4Query       :: H.Query              -- ^ Parsed query string information
        , s4Body        :: B.ByteString         -- ^ Body of request

        -- These fields are for internal use: set them up with Nothing
        -- (will be filled in by complete_sign4, below)
                                
        , s4SgndHeaders :: Maybe B.ByteString   -- ^ Signed headers    (internally calculated)
        , s4CnclHeaders :: Maybe B.ByteString   -- ^ Canonical headers (internally calculated)
        }
    deriving (Typeable)


-- | Generate authorization header (s4Authz) and intermediate steps for
-- diagnostics and validation (s4StringToSign,s4canonicalRequest) from the
-- Sign4 parameters.

s4Authz, s4StringToSign, s4CanonicalRequest :: Sign4 -> B.ByteString

s4Authz            = s4Authz_            . complete_sign4
s4StringToSign     = s4StringToSign_     . complete_sign4
s4CanonicalRequest = s4CanonicalRequest_ . complete_sign4


-- s4Authz_, s4Singn4_, s4StringToSign_ & s4CanonicalRequest all generate
-- from Sign4 parameters that have been completed (see complete_sign4, below). 

s4Authz_ :: Sign4 -> B.ByteString
s4Authz_ s4@Sign4{..} =
    Bl.toByteString . mconcat $
        [ Bl.copyByteString   algorithm
        , Bl.copyByteString   " Credential="
        , Bl.copyByteString $ accessKeyID s4Credentials
        , Bl.copyByteString   "/"
        , Bl.copyByteString $ credential_scope s4
        , Bl.copyByteString   ", SignedHeaders="
        , Bl.copyByteString $ fromJustNote "authz:sgh" s4SgndHeaders
        , Bl.copyByteString   ", Signature="
        , Bl.copyByteString $ s4Sign4_ s4
        ]

s4Sign4_ :: Sign4 -> B.ByteString
s4Sign4_ s4@Sign4{..} =
    to_hex                                    $
        s4_hmac' (s4StringToSign_ s4)         $
        s4_hmac' "aws4_request"               $
        s4_hmac' s4Service                    $
        s4_hmac' s4Endpoint                   $
        s4_hmac' (BC.pack $ mere_date s4Date) $
            "AWS4" `B.append` secretAccessKey s4Credentials

s4StringToSign_ :: Sign4 -> B.ByteString
s4StringToSign_ s4@Sign4{..} = 
    Bl.toByteString . mconcat . build_lines $
        [ Bl.copyByteString   algorithm
        , Bl.copyByteString $ fmtTime iso8601BasicUtcDate s4Date
        , Bl.copyByteString $ credential_scope s4
        , Bl.copyByteString $ s4_hash_hex $ s4CanonicalRequest_ s4
        ]

s4CanonicalRequest_ :: Sign4 -> B.ByteString
s4CanonicalRequest_ Sign4{..} = 
    Bl.toByteString . mconcat . build_lines $
        [ Bl.copyByteString s4Method
        , Bl.copyByteString pth 
        , Bl.copyByteString qry
        , Bl.copyByteString chs
        , Bl.copyByteString sgh
        , Bl.copyByteString hxp
        ]
  where
    qry = render_query $ sort s4Query

    hxp = s4_hash_hex s4Body

    pth = normalize_path s4Path

    sgh = fromJustNote "canonicalRequest:sgh" s4SgndHeaders
    
    chs = fromJustNote "canonicalRequest:sgh" s4CnclHeaders
    
complete_sign4 :: Sign4 -> Sign4
complete_sign4 s4@Sign4{..} = 
    s4  { s4SgndHeaders = Just sgh
        , s4CnclHeaders = Just chs
        }
  where
    sgh = BC.intercalate (BC.singleton ';') $ map (CI.original . fst) hds

    chs = B.concat $ map mkh hds
    
    hds = map bunch_hs $ groupBy (\x y->fst x==fst y) $ sort s4Headers

    mkh = \(hnm,hvl) ->
                Bl.toByteString . mconcat $
                    [ Bl.copyByteString $ BC.map toLower $ CI.original hnm
                    , Bl.copyByteString   ":"
                    , Bl.copyByteString $ trim hvl
                    , Bl.copyByteString   "\n"
                    ]

credential_scope :: Sign4 -> B.ByteString
credential_scope Sign4{..} =
    BC.pack $ printf "%s/%s/%s/aws4_request"
                (mere_date s4Date) (BC.unpack s4Endpoint) (BC.unpack s4Service)

algorithm :: B.ByteString
algorithm = "AWS4-HMAC-SHA256"

mere_date :: UTCTime -> String
mere_date = formatTime defaultTimeLocale "%Y%m%d"

build_lines :: [Bl.Builder] -> [Bl.Builder]
build_lines = intersperse (Bl8.fromChar '\n')


-- Convert the like of
--      //foo//bar/../baz
-- into
--      /foo/baz

normalize_path :: B.ByteString -> B.ByteString
normalize_path = BC.pack . mng . BC.unpack
  where
    -- break path into elements and squashes "." and ".." elements
    -- all paths start with "/"
    -- if input path ends with a "/" then ensure same for output
    -- mostly works with reversed list of path elements
       
    mng s = ("/" ++) $ intercalate "/" $ reverse $ 
                case sqh $ reverse $ els s of
                  h:t | lastDef ' ' s=='/' -> (h++"/") : t
                  res                      -> res 

    -- split out path elements: defn of words with ('/'==) for isSpace

    els s = case dropWhile ('/'==) s of
              "" -> []
              s' -> e : els s''
                  where
                    (e, s'') = break ('/'==) s'
    
    -- squash ".." and "." elements out of reversed path
    
    sqh []    = []
    sqh (l:i) =
        case l of
          "."  ->            sqh i
          ".." -> tailSafe $ sqh i
          _    -> l :        sqh i

-- Group a list of headers with the same name, normaizing the header name
-- to lower case; e.g., from  
--      Foo:a
--      FOO:b
-- into
--      foo:a,b

bunch_hs :: [H.Header] -> H.Header
bunch_hs []            = error "bunch_hs precondition"
bunch_hs (p@(hn,_):ps) =
        ( CI.mk $ BC.map toLower $ CI.original hn
        , BC.intercalate (BC.singleton ',') $ map snd $ p:ps
        )

s4_hash_hex :: B.ByteString -> B.ByteString
s4_hash_hex = digestToHexByteString . sha256

s4_hmac' :: B.ByteString -> B.ByteString -> B.ByteString
s4_hmac' = flip s4_hmac

s4_hmac :: B.ByteString -> B.ByteString -> B.ByteString
s4_hmac key = toBytes . hmac sha256 64 key

sha256 :: B.ByteString -> Digest SHA256
sha256 = hash

trim :: B.ByteString -> B.ByteString
trim bs0 = B.take n bs
  where
    n = headDef 0 $ map (+1) $
            dropWhile (isSpace . BC.index bs) [B.length bs-1,B.length bs-2..0]
  
    bs = BC.dropWhile isSpace bs0
        
-- adapted from http-types (Network.HTTP.Types.URI), to display
-- empty query parameters with strings
        
render_query :: H.Query -> B.ByteString
render_query = Bl.toByteString . render_query_b

render_query_b :: H.Query -> Bl.Builder
render_query_b []     = mempty
render_query_b (p:ps) = mconcat $ go mempty p : map (go amp) ps
  where
    go sep (k, mv) = 
        mconcat 
            [ sep
            , urlEncodeBuilder True k
            , eql `mappend` urlEncodeBuilder True (maybe BC.empty id mv)
            ]

    amp = Bl.copyByteString "&"
    eql = Bl.copyByteString "="

to_hex :: B.ByteString -> B.ByteString
to_hex = BC.pack . foldr f "" . BC.unpack
  where
    f c t = intToDigit (n `div` 16) : intToDigit (n `mod` 16) : t
          where
            n = ord c

-- generate a 'canonical' ISO 8601 UTC date

iso8601BasicUtcDate :: String
iso8601BasicUtcDate = "%Y%m%dT%H%M%SZ"
