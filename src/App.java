public class App {

    public static void main(String[] args) {
        RSATest();
        ReadTaskFromFile();
    }

    public static void ReadTaskFromFile() {
        RSAEncryption rsa = new RSAEncryption();
        // Print current folder
        rsa.ReadSecretKeyFromFile("./src/Task/sk.txt");

        String decryptedText = rsa.DecryptFromFile("./src/Task/chiffre.txt");
        System.out.println("Decrpyted Task: " + decryptedText);
    }

    public static void RSATest() {
        RSAEncryption rsa = new RSAEncryption(1024);
        rsa.GenerateKeys();

        // Encrypt and decrypt a message
        String encrypted = rsa.EncryptMessage("Hello World");
        String decrypted = rsa.DecryptMessage(encrypted);
        System.out.println("Decrypted string: " + decrypted);

        String message = rsa.ReadFromFile("./src/text.txt");
        // Write keys to files
        rsa.WriteSecretKeyToFile("./src/sk.txt");
        rsa.WritePublicKeyToFile("./src/pk.txt");

        // Write message to file and read it
        rsa.EncryptToFile(message, "./src/chiffre.txt");
        String decryptedFromFile = rsa.DecryptFromFile("./src/chiffre.txt");
        rsa.WriteToFile("./src/text-d.txt", decryptedFromFile);
        System.out.println("Decrypted file: " + decryptedFromFile);
    }
}
