import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.*;
import com.github.scribejava.core.oauth.OAuthService;

public class OAuthExample {

    public static void main(String[] args) {
        // Replace these with your actual API key and secret
        String apiKey = "your_api_key";
        String apiSecret = "your_api_secret";

        OAuthService service = new ServiceBuilder(apiKey)
                .apiSecret(apiSecret)
                .build(ScribeApi.instance());

        // Now you can use the 'service' instance to make OAuth requests
        // For example, fetching a request token
        OAuth1RequestToken requestToken = service.getRequestToken();

        System.out.println("Got Request Token!");
        System.out.println("Token: " + requestToken.getToken());
        System.out.println("Token Secret: " + requestToken.getTokenSecret());
    }
}
