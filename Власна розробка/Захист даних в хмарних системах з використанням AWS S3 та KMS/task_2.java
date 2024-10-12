import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

import java.io.File;

public class S3KMSEncryptionExample {

    public static void main(String[] args) {
        String bucketName = "my-unique-bucket-name";
        String keyName = "myfile.txt";
        String filePath = "path/to/your/file.txt";

        try {
            // Ініціалізація клієнтів S3 та KMS
            S3Client s3Client = S3Client.builder()
                    .region(Region.EU_WEST_1)
                    .credentialsProvider(ProfileCredentialsProvider.create())
                    .build();

            KmsClient kmsClient = KmsClient.builder()
                    .region(Region.EU_WEST_1)
                    .credentialsProvider(ProfileCredentialsProvider.create())
                    .build();

            // Створення ключа KMS
            CreateKeyResponse createKeyResponse = kmsClient.createKey(CreateKeyRequest.builder().build());
            String kmsKeyId = createKeyResponse.keyMetadata().keyId();

            // Завантаження файлу з шифруванням SSE-KMS
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(keyName)
                    .serverSideEncryption("aws:kms")
                    .ssekmsKeyId(kmsKeyId)
                    .build();

            PutObjectResponse putObjectResponse = s3Client.putObject(putObjectRequest,
                    RequestBody.fromFile(new File(filePath)));

            System.out.println("Файл успішно завантажено з шифруванням SSE-KMS: " + putObjectResponse.eTag());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}