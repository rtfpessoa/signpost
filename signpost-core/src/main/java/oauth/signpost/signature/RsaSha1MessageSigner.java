package oauth.signpost.signature;

import oauth.signpost.OAuth;
import oauth.signpost.exception.OAuthMessageSignerException;
import oauth.signpost.http.HttpParameters;
import oauth.signpost.http.HttpRequest;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@SuppressWarnings("serial")
public class RsaSha1MessageSigner extends OAuthMessageSigner {

    @Override
    public String getSignatureMethod() {
        return "RSA-SHA1";
    }

    @Override
    public String sign(HttpRequest request, HttpParameters requestParams)
            throws OAuthMessageSignerException {
        byte[] keyBytes;
        byte[] signedBytes;
        String sbs = new SignatureBaseString(request, requestParams).generate();
        try {
            keyBytes = sbs.getBytes(OAuth.ENCODING);
            signedBytes = signBytes(keyBytes);
        } catch (InvalidKeyException e) {
            throw new OAuthMessageSignerException(e);
        } catch (InvalidKeySpecException e) {
            throw new OAuthMessageSignerException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new OAuthMessageSignerException(e);
        } catch (SignatureException e) {
            throw new OAuthMessageSignerException(e);
        } catch (UnsupportedEncodingException e) {
            throw new OAuthMessageSignerException(e);
        }

        return base64Encode(signedBytes).trim();
    }

    private byte[] signBytes(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        Signature signer;
        signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(getPrivateKey());
        signer.update(keyBytes);
        return signer.sign();
    }

    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyString = getConsumerSecret();
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        return privateKeyFactory.generatePrivate(privateKeySpec);
    }

}
