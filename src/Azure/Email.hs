{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wall #-}

module Azure.Email
  ( sendEmail
  , sendHtmlEmail
  , fetchAzureToken
  , Email(..)
  , AzureToken(..)
  , AzureCreds(..)
  ) where

import Codec.Crypto.RSA.Pure (PrivateKey)
import Control.Monad.Catch (MonadThrow, Exception, throwM)
import Data.Aeson ((.=),object)
import Data.Aeson.Lens (_String,key)
import Data.Function ((&))
import Data.Functor (void)
import Data.Monoid((<>))
import Data.Text (Text)
import Data.Time (UTCTime, addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.UUID (UUID)
import Lens.Micro ((^?),(.~))
import Network.HTTP.Client (Manager)
import Network.Wreq
import qualified Codec.Crypto.RSA.Pure as RSA
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Base64.Lazy as Base64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID4

data Email = Email
  { recipientAddress :: !Text
  , senderAddress    :: !Text
  , subject          :: !Text
  , body             :: !Text
  }

sendEmailInternal ::
     IsHtml 
  -> Manager -- ^ HTTP manager
  -> AzureToken -- ^ token
  -> Email
  -> IO ()
sendEmailInternal isHtml mngr token (Email recipientEmail senderEmail subject' textBody) =
  void $ postWith opts
    (Text.unpack (Text.concat ["https://outlook.office365.com/api/v1.0/users/", senderEmail, "/sendmail"]))
    body'
  where
    opts = defaults
      & manager .~ Right mngr
      & header "Authorization" .~ [TextEncoding.encodeUtf8 $ "Bearer " <> getAzureToken token]
    body' = object
      [ "Message" .= object
        [ "Subject" .= subject'
        , "Body"    .= object
          [ "Content" .= textBody
          , "ContentType" .= isHtmlToContentType isHtml
          ]
        , "ToRecipients" .=
          [ object
            [ "EmailAddress" .= object
               [ "Address" .= recipientEmail
               ]
            ]
          ]
        ]
      , "SaveToSentItems" .= True
      ]

sendEmail ::
     Manager
  -> AzureToken
  -> Email 
  -> IO ()
sendEmail = sendEmailInternal IsNotHtml

sendHtmlEmail ::
     Manager
  -> AzureToken
  -> Email
  -> IO ()
sendHtmlEmail = sendEmailInternal IsHtml


data IsHtml = IsHtml | IsNotHtml

isHtmlToContentType :: IsHtml -> Text
isHtmlToContentType = \case { IsHtml -> "HTML"; IsNotHtml -> "Text" }

asInt :: Int -> Int; asInt = id
asText :: Text -> Text; asText = id

buildAssertion :: PrivateKey -> Text -> UUID -> UUID -> UUID -> UTCTime -> Text
buildAssertion privateKey base64Fingerprint clientId tenantId requestId now =
  TextEncoding.decodeUtf8 $ BL.toStrict $ mempty
    <> encodedHeaderAndPayload
    <> "."
    <> Base64.encode ( fromRightErr "buildAssertion: RSA signing failed"
                       $ RSA.sign privateKey encodedHeaderAndPayload
                     )
  where
    encodedHeaderAndPayload = mempty
      <> Base64.encode (Aeson.encode theHeader)
      <> "."
      <> Base64.encode (Aeson.encode payload)
    theHeader = object
      [ "alg" .= asText "RS256"
      , "x5t" .= base64Fingerprint
      ]
    payload = object
      [ "aud" .= Text.concat ["https://login.microsoftonline.com/", uuidToText tenantId, "/oauth2/token"]
      , "sub" .= uuidToText clientId
      , "iss" .= uuidToText clientId
      , "jti" .= uuidToText requestId
      , "nbf" .= asInt (round $ utcTimeToPOSIXSeconds now)
      , "exp" .= asInt (round $ utcTimeToPOSIXSeconds $ addUTCTime 180 now)
      ]
  
uuidToText :: UUID -> Text
uuidToText = TextEncoding.decodeUtf8 . UUID.toASCIIBytes

fetchAzureToken :: Manager -> AzureCreds -> IO AzureToken
fetchAzureToken mngr creds@(AzureCreds clientId tenantId fingerPrint privateKey) = do
  let opts = defaults & manager .~ Right mngr
  now <- getCurrentTime
  requestId <- UUID4.nextRandom
  r <- postWith opts (Text.unpack (Text.concat ["https://login.microsoftonline.com/", uuidToText (azureTenantId creds), "/oatuh2/token"]))
         $ buildFormParams "https://outlook.office365.com/"
             privateKey
             fingerPrint
             clientId
             tenantId
             requestId
             now
  t <- throwFromJust "Could not get an access token" $ r ^? responseBody . key "access_token" . _String
  pure $ AzureToken t

buildFormParams :: Text -> PrivateKey -> Text -> UUID -> UUID -> UUID -> UTCTime -> [FormParam]
buildFormParams resource privateKey base64Fingerprint clientId tenantId requestId now =
  [ "grant_type"            := asText "client_credentials"
  , "resource"              := resource
  , "client_id"             := uuidToText clientId
  , "client_assertion_type" := asText "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  , "client_assertion"      := buildAssertion privateKey base64Fingerprint clientId tenantId requestId now
  ]

newtype AzureToken = AzureToken { getAzureToken :: Text }

data AzureCreds = AzureCreds
  { azureClientId    :: !UUID
  , azureTenantId    :: !UUID
  , azureFingerprint :: !Text
  , azurePrivateKey  :: !PrivateKey
  }

fromRightErr :: String -> Either a b -> b
fromRightErr err = \case
  Left  _ -> error err
  Right b -> b

throwFromJust :: MonadThrow m => String -> Maybe a -> m a
throwFromJust err = \case
  Just a  -> pure a
  Nothing -> throwM (MyException err)

data MyException = MyException String
  deriving (Show, Eq)
instance Exception MyException
