package com.softwareverde.security.dukpt;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class DukptTests {
    @Test
    public void testDecryptValidData() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        data = Dukpt.decryptTripleDes(key, data);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testEncrypt() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        encryptedPayload = Dukpt.encryptTripleDes(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptTripleDes(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();

        // Assert
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testGetIpek() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "629949012C0000000003";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        // Action
        final DukptVariant dukptVariant = new DukptVariant();
        BitSet ipek = dukptVariant.getIpek(Dukpt.toBitSet(bdk), Dukpt.toBitSet(ksn));

        // Assert
        Assert.assertEquals("D2943CCF80F42E88E23C12D1162FD547", Dukpt.toHex(Dukpt.toByteArray(ipek)));
    }

    @Test
    public void testToDataKey() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        // Action
        final DukptVariant dukptVariant = new DukptVariant(Dukpt.KEY_REGISTER_BITMASK, Dukpt.DATA_VARIANT_BITMASK);
        byte[] derivedKey = dukptVariant.computeKey(bdk, ksn);
        byte[] dataKey = dukptVariant.toDataKey(derivedKey);

        // Assert
        Assert.assertEquals("C39B2778B058AC376FB18DC906F75CBA", Dukpt.toHex(dataKey));
    }

    @Test
    public void testDecryptValidDataWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        data = Dukpt.decryptTripleDes(key, data);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testEncryptWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        encryptedPayload = Dukpt.encryptTripleDes(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptTripleDes(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();

        // Assert
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testToDataKeyWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        // Action
        final DukptVariant dukptVariant = new DukptVariant(Dukpt.KEY_REGISTER_BITMASK, Dukpt.DATA_VARIANT_BITMASK);
        byte[] derivedKey = dukptVariant.computeKeyFromIpek(ipek, ksn);
        byte[] dataKey = dukptVariant.toDataKey(derivedKey);

        // Assert
        Assert.assertEquals("C39B2778B058AC376FB18DC906F75CBA", Dukpt.toHex(dataKey));
    }

    @Test
    public void testAESDecryptValidData() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "9D47070F3E8D8876AEA12F56C711177A30F44225FC9998805BF2A899E0BFCD2ABE6539CE9078E97BE85C8AD5363B27CD438F92762C3E009651715DF4F7DF6167B88884D698F08A84382192EB1567C93E";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        data = Dukpt.decryptAes(key, data, true);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testAESEncrypt() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";
        String expectedEncrypted = "DEF068DC6BFA9DB95707BD3453583D12C0E87DA90FD1B3360190ACE1185587AA";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        encryptedPayload = Dukpt.encryptAes(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptAes(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();
        String encryptedOutput = Dukpt.toHex(encryptedPayload);

        // Assert
        Assert.assertEquals(expectedEncrypted, encryptedOutput);
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testAESDecryptValidDataWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "9D47070F3E8D8876AEA12F56C711177A30F44225FC9998805BF2A899E0BFCD2ABE6539CE9078E97BE85C8AD5363B27CD438F92762C3E009651715DF4F7DF6167B88884D698F08A84382192EB1567C93E";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        data = Dukpt.decryptAes(key, data, true);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testAESEncryptWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";
        String expectedEncrypted = "DEF068DC6BFA9DB95707BD3453583D12C0E87DA90FD1B3360190ACE1185587AA";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        encryptedPayload = Dukpt.encryptAes(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptAes(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();
        String encryptedOutput = Dukpt.toHex(encryptedPayload);

        // Assert
        Assert.assertEquals(expectedEncrypted, encryptedOutput);
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testAES192DecryptValidData() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "9949FA820F5491C4113314395F74D9ACE904C6771C136EFC4DAF493E3A7354EE743E7AD94672A466854EAD1C195D7D6BC79E5A568C2F7D763F6C2C95A482CA38154C6E077134C6AF7076AD9BEA0D11A4";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        data = Dukpt.decryptAes192(key, data, true);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testAES192Encrypt() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";
        String expectedEncrypted = "FAF2C00F25EB47D8114DBE76332B3BBB3BF177A94FF6288C81F197EC009007FC";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        encryptedPayload = Dukpt.encryptAes192(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptAes192(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();
        String encryptedOutput = Dukpt.toHex(encryptedPayload);

        // Assert
        Assert.assertEquals(expectedEncrypted, encryptedOutput);
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testAES192DecryptValidDataWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "9949FA820F5491C4113314395F74D9ACE904C6771C136EFC4DAF493E3A7354EE743E7AD94672A466854EAD1C195D7D6BC79E5A568C2F7D763F6C2C95A482CA38154C6E077134C6AF7076AD9BEA0D11A4";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        data = Dukpt.decryptAes192(key, data, true);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testAES192EncryptWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";
        String expectedEncrypted = "FAF2C00F25EB47D8114DBE76332B3BBB3BF177A94FF6288C81F197EC009007FC";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        encryptedPayload = Dukpt.encryptAes192(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptAes192(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();
        String encryptedOutput = Dukpt.toHex(encryptedPayload);

        // Assert
        Assert.assertEquals(expectedEncrypted, encryptedOutput);
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testAES256DecryptValidData() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "D380C323AF8D72A72671E0559C41368F2E552FC2C5A9FD5E9B42214BA2EA69F1EB71D5D91156E0FB77194226C886633E54149C47CDD0F9EF92E75A56813865D7F08D50155987E61A5E9144BBB2F7D48C";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        data = Dukpt.decryptAes256(key, data, true);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testAES256Encrypt() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";
        String expectedEncrypted = "9BEFCE4DC1D681FDBB85894A8F38D10873048C7035850F5C9E6CD674E1FE548C";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        encryptedPayload = Dukpt.encryptAes256(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptAes256(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();
        String encryptedOutput = Dukpt.toHex(encryptedPayload);

        // Assert
        Assert.assertEquals(expectedEncrypted, encryptedOutput);
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testAES256DecryptValidDataWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "D380C323AF8D72A72671E0559C41368F2E552FC2C5A9FD5E9B42214BA2EA69F1EB71D5D91156E0FB77194226C886633E54149C47CDD0F9EF92E75A56813865D7F08D50155987E61A5E9144BBB2F7D48C";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        data = Dukpt.decryptAes256(key, data, true);
        String dataOutput = new String(data, StandardCharsets.UTF_8);

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testAES256EncryptWithIpek() throws Exception {
        // Setup
        String ipekHexString = "6AC292FAA1315B4D858AB3A3D7D5933A";
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";
        String expectedEncrypted = "9BEFCE4DC1D681FDBB85894A8F38D10873048C7035850F5C9E6CD674E1FE548C";

        byte[] ipek = Dukpt.toByteArray(ipekHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKeyFromIpek(ipek, ksn);
        encryptedPayload = Dukpt.encryptAes256(key, payloadString.getBytes(StandardCharsets.UTF_8), true);
        decryptedPayload = Dukpt.decryptAes256(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, StandardCharsets.UTF_8).trim();
        String encryptedOutput = Dukpt.toHex(encryptedPayload);

        // Assert
        Assert.assertEquals(expectedEncrypted, encryptedOutput);
        Assert.assertEquals(payloadString, dataOutput);
    }
}
