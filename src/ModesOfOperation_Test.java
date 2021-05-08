public class ModesOfOperation_Test {
    public static void main(String[] args) {
       MGM test = new MGM();
       test.Encrypt("resources/File_5MB.txt", "resources/AAD.txt", "1234567812345678");
       System.out.println(
               test.Decrypt("resources/File_5MB.txt.crptd", "resources/AAD.txt", "1234567812345678")
       );
    }
}
