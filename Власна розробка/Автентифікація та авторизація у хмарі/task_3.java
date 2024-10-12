import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

public class CognitoAuthenticationExample {

    private static final String USER_POOL_ID = "your-user-pool-id";
    private static final String CLIENT_ID = "your-client-id";

    public static void main(String[] args) {
        try {
            // Ініціалізація клієнта Cognito
            CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                    .region(Region.US_EAST_1)
                    .credentialsProvider(ProfileCredentialsProvider.create())
                    .build();

            // Приклад автентифікації користувача
            String username = "your-username";
            String password = "your-password";
            String authToken = authenticateUser(cognitoClient, username, password);

            if (authToken != null) {
                System.out.println("Користувач успішно автентифікований. Токен: " + authToken);
            } else {
                System.out.println("Помилка автентифікації.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String authenticateUser(CognitoIdentityProviderClient cognitoClient, String username, String password) {
        try {
            // Створення запиту на автентифікацію
            InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .clientId(CLIENT_ID)
                    .authParameters(java.util.Map.of(
                            "USERNAME", username,
                            "PASSWORD", password
                    ))
                    .build();

            // Виконання запиту на автентифікацію
            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);

            // Отримання токена доступу
            return authResponse.authenticationResult().accessToken();

        } catch (NotAuthorizedException e) {
            System.out.println("Неправильний логін або пароль.");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}