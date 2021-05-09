public class ModesOfOperation_Test {

   public void testModesOfOperation(String path, String key, String aad_path, int R) {
       CBC test_cbc = new CBC();
       OFB test_ofb = new OFB();
       OMAC test_omac = new OMAC();
       MGM test_mgm = new MGM();
       CTR_ACPKM test_ctr_acpkm = new CTR_ACPKM();
       long time;

       time = System.nanoTime();
       long[] mac = test_omac.getMAC(path, key);
       System.out.println("MAC: "+Long.toHexString(mac[0])+" "+Long.toHexString(mac[1]));
       System.out.println("(OMAC) MAC calculated in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds\n");

       time = System.nanoTime();
       test_cbc.Encrypt(path, key);
       System.out.println("(CBC) Encryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds");
       time = System.nanoTime();
       test_cbc.Decrypt(path+".crptd", key);
       System.out.println("(CBC) Decryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds\n");

       time = System.nanoTime();
       test_ofb.Encrypt(path, key);
       System.out.println("(OFB) Encryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds");
       time = System.nanoTime();
       test_ofb.Decrypt(path+".crptd", key);
       System.out.println("(OFB) Decryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds\n");

       time = System.nanoTime();
       test_ctr_acpkm.Encrypt(path, key, R);
       System.out.println("(CTR-ACPKM) Encryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds");
       time = System.nanoTime();
       test_ctr_acpkm.Decrypt(path+".crptd", key, R);
       System.out.println("(CTR-ACPKM) Decryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds\n");

       time = System.nanoTime();
       test_mgm.Encrypt(path, aad_path, key);
       System.out.println("(MGM) Encryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds");
       time = System.nanoTime();
       boolean mac_b = test_mgm.Decrypt(path+".crptd", aad_path, key);
       System.out.println("(MGM) Decryption done in "+
               String.format("%.3f", ((System.nanoTime() - time) * 0.000000001))+" seconds");
       System.out.println(mac_b ? "MGM MAC correct\n" : "MGM MAC incorrect\n");


       mac = test_omac.getMAC(path, key);
       System.out.println("MAC: "+Long.toHexString(mac[0])+" "+Long.toHexString(mac[1]));
   }


   public static void main(String[] args) {
       ModesOfOperation_Test test = new ModesOfOperation_Test();
       test.testModesOfOperation("resources/File_5MB.txt", "123456788765432111223344",
               "resources/AAD.txt", 30);

   }
}
