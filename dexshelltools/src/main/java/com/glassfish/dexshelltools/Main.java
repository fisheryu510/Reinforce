package com.glassfish.dexshelltools;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;

public class Main {

    public static void main(String[] args) throws Exception {
//        System.out.println(Main.class.getResource(""));
//        File nullFile = new File("");
//        System.out.println(nullFile.getAbsolutePath());
        //源程序
        File payloadSrcFile = new File("force/ForceApkObj.apk");
        System.out.println("size of apk: " + payloadSrcFile.length());
        //读取加密程序的dex文件
        File unShellDexFile = new File("force/ShellApk.dex");
        byte[] unShellDexArray = readFileBytes(unShellDexFile);

        //读取源程序并加密
        byte[] payloadArray = encrypt(readFileBytes(payloadSrcFile));


        //根据加密后源程序的大小和加密apk的dex文件大小，计算出更新后的大小
        int payloadLen = payloadArray.length;
        int unShellDexLen = unShellDexArray.length;
        int totalLen = payloadLen + unShellDexLen + 4;
        byte[] newDexArray = new byte[totalLen];

        //分别拷贝加密apk的dex文件、加密后的源程序、以及总长度到新的dex文件中
        System.arraycopy(unShellDexArray, 0, newDexArray, 0, unShellDexLen);
        System.arraycopy(payloadArray, 0, newDexArray, unShellDexLen, payloadLen);
        System.arraycopy(int2byte(payloadLen), 0, newDexArray, totalLen - 4, 4);

        /*
        分别修复文件头、文件签名、文件checksum
        由于file_size属于signature需要校验的内容中，因此一定要先修复file_size
        signature和checksum的关系同理
        需要注意各个节点在文件中起始位置和大小
         */
        fixHeaderFileSize(newDexArray);
        fixHeaderSignature(newDexArray);
        fixHeaderChecksum(newDexArray);

        String newDexFile = "force/classes.dex";
        try {
            boolean isSuccess = false;
            File file = new File(newDexFile);
            if (!file.exists()) {
                isSuccess = file.createNewFile();
            }
            if (!isSuccess) {
                System.out.println("Create new  Dex File Failed");
                return;
            }
            FileOutputStream fos = new FileOutputStream(newDexFile);
            fos.write(newDexArray);
            fos.flush();
            fos.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }

    }

    private static byte[] encrypt(byte[] srcData) {
        for (int i = 0; i < srcData.length; i++) {
            // XOR 异或方式实现简单加密
            srcData[i] = (byte)(0xFF ^ srcData[i]);
        }
        return srcData;
    }

    private static void fixHeaderChecksum(byte[] dexBytes) {
        Adler32 adler = new Adler32();
        //修改checksum，checksum不校验8字节的magic number和自身
        adler.update(dexBytes, 12, dexBytes.length - 12);

        long value = adler.getValue();
        int va = (int)value;
        byte[] newChecksum = int2byte(va);
        byte[] reverseChecksum = new byte[4];

        //由于int2byte转换之后的结果是逆序的因此需要反转结果
        int sizeOfChecksum = newChecksum.length;
        for (int i = 0; i < 4; i++) {
            reverseChecksum[i] = newChecksum[sizeOfChecksum - 1 - i];
            System.out.println(Integer.toHexString(newChecksum[i]));
        }
        System.arraycopy(reverseChecksum, 0, dexBytes, 8, 4);
        System.out.println(Long.toHexString(value));
        System.out.println();
    }

    /**
     * 将int型转换为字节数组，转换之后的结果是逆序的
     * 如输入为231：转换之后的结果为e7 00 00 00
     * @param value
     * @return
     */
    private static byte[] int2byte(int value) {
        byte[] b = new byte[4];
        for (int i = 3; i >= 0; i--) {
            b[i] = (byte)(value%256);
            value >>=8;
        }
        return b;
    }


    private static void fixHeaderSignature(byte[] dexBytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(dexBytes, 32, dexBytes.length - 32);
        byte[] newDigest = md.digest();
        System.arraycopy(newDigest, 0, dexBytes, 12, 20);
        String hexStr = "";
        //打印签名的16进制值，byte需要先转换为整形才能然后才能打印
        for (int i = 0; i < newDigest.length; i++) {
            hexStr += Integer.toString((newDigest[i] & 0xFF) + 0x100, 16)
                    .substring(1);
        }

        System.out.println(hexStr);
    }

    private static void fixHeaderFileSize(byte[] dexBytes) {
        byte[] fileSize = int2byte(dexBytes.length);
        System.out.println(Integer.toHexString(dexBytes.length));
        byte[] refs = new byte[4];
        int lengthOfFileSize = fileSize.length;
        for (int i = 0; i < 4; i++) {
            refs[i] = fileSize[lengthOfFileSize - i - 1];
            System.out.println(Integer.toHexString(fileSize[i]));
        }
        System.arraycopy(refs, 0, dexBytes, 32, 4);
    }

    private static byte[] readFileBytes(File file) throws IOException {
        byte[] buffer = new byte[1024];
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream(file);
        while (true) {
            int readSize = fis.read(buffer);
            if (readSize != -1) {
                bos.write(buffer, 0, readSize);
            } else {
                return bos.toByteArray();
            }
        }
    }

}
