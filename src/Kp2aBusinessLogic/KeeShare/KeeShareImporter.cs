using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using keepass2android.Io;

namespace keepass2android.KeeShare
{
    public class KeeShareImporter
    {
        private const string SignatureFileName = "container.share.signature";
        private const string ContainerFileName = "container.share.kdbx";

        public static void CheckAndImport(Database db, IKp2aApp app)
        {
            if (db == null || db.Root == null) return;

            // Iterate over all groups to find share references
            var groupsToProcess = new List<Tuple<PwGroup, KeeShareSettings.Reference>>();

            // Collect groups first to avoid modification during iteration if that were an issue (though we only merge content)
            var allGroups = db.Root.GetGroups(true);
            allGroups.Add(db.Root); // Include root? Usually shares are sub-groups.

            foreach (var group in allGroups)
            {
                var reference = KeeShareSettings.GetReference(group);
                if (reference != null && reference.IsImporting)
                {
                    groupsToProcess.Add(new Tuple<PwGroup, KeeShareSettings.Reference>(group, reference));
                }
            }

            foreach (var tuple in groupsToProcess)
            {
                var group = tuple.Item1;
                var reference = tuple.Item2;
                ImportShare(db, app, group, reference);
            }
        }

        private static void ImportShare(Database db, IKp2aApp app, PwGroup targetGroup, KeeShareSettings.Reference reference)
        {
            try
            {
                // Resolve Path
                string path = reference.Path;

                IOConnectionInfo ioc = ResolvePath(db.Ioc, path, app);
                if (ioc == null)
                {
                    return;
                }

                byte[] dbData = null;

                IFileStorage storage = app.GetFileStorage(ioc);

                using (var stream = storage.OpenFileForRead(ioc))
                {
                    if (stream == null) return;

                    // Read into memory because we might need random access (Zip) or read twice
                    using (var ms = new MemoryStream())
                    {
                        stream.CopyTo(ms);
                        ms.Position = 0;

                        if (IsZipFile(ms))
                        {
                            dbData = ReadFromContainer(ms, reference);
                        }
                        else
                        {
                            // Assume plain KDBX
                            dbData = ms.ToArray();
                        }
                    }
                }

                if (dbData != null)
                {
                    MergeDatabase(db, targetGroup, dbData, reference.Password);
                }
            }
            catch (Exception ex)
            {
                Kp2aLog.Log("KeeShare Import Error: " + ex.Message);
            }
        }

        private static bool IsZipFile(Stream stream)
        {
            if (stream.Length < 4) return false;
            var buf = new byte[4];
            stream.Read(buf, 0, 4);
            stream.Position = 0;
            return buf[0] == 0x50 && buf[1] == 0x4B && buf[2] == 0x03 && buf[3] == 0x04;
        }

        private static byte[] ReadFromContainer(MemoryStream zipStream, KeeShareSettings.Reference reference)
        {
            try
            {
                using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Read))
                {
                    var sigEntry = archive.GetEntry(SignatureFileName);
                    var dbEntry = archive.GetEntry(ContainerFileName);

                    if (dbEntry == null) return null;

                    byte[] dbData;
                    using (var s = dbEntry.Open())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        dbData = ms.ToArray();
                    }

                    if (sigEntry != null)
                    {
                        string sigXml;
                        using (var s = sigEntry.Open())
                        using (var sr = new StreamReader(s, Encoding.UTF8))
                        {
                            sigXml = sr.ReadToEnd();
                        }

                        if (!VerifySignature(dbData, sigXml))
                        {
                            Kp2aLog.Log("KeeShare: Signature verification failed for " + reference.Path);
                            // If verification fails, we definitely shouldn't import.
                            return null;
                        }
                    }

                    return dbData;
                }
            }
            catch (Exception ex)
            {
                Kp2aLog.Log("KeeShare: Error reading container: " + ex.Message);
                return null;
            }
        }

        private static bool VerifySignature(byte[] data, string sigXml)
        {
            var sig = KeeShareSignature.Parse(sigXml);
            if (sig == null || sig.Key == null || string.IsNullOrEmpty(sig.Signature))
            {
                return false;
            }

            try
            {
                var rsaParams = sig.Key.Value;
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(rsaParams);

                    // Signature format is "rsa|HEX_ENCODED_SIGNATURE"
                    if (!sig.Signature.StartsWith("rsa|")) return false;
                    var hexSig = sig.Signature.Substring(4);
                    var sigBytes = HexStringToByteArray(hexSig);

                    return rsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                Kp2aLog.Log("KeeShare: Verification exception: " + ex.Message);
                return false;
            }
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0) return null;
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        private static void MergeDatabase(Database mainDb, PwGroup targetGroup, byte[] dbData, string password)
        {
            var pwDatabase = new PwDatabase();
            var compKey = new CompositeKey();
            compKey.AddUserKey(new KcpPassword(password));

            try
            {
                using (var ms = new MemoryStream(dbData))
                {
                    pwDatabase.Open(ms, compKey, null);
                }

                // Use a temporary database to merge into targetGroup without polluting mainDb global properties (name, recycle bin etc)
                // and to avoid merging into mainDb root.

                var tempDb = new PwDatabase();
                tempDb.New(new IOConnectionInfo(), new CompositeKey(), "Temp");
                // Set RootGroup to targetGroup so MergeIn traverses targetGroup
                tempDb.RootGroup = targetGroup;

                // Sync deleted objects and icons so MergeIn works correctly with existing state
                if (mainDb.KpDatabase.DeletedObjects != null)
                {
                    foreach (var del in mainDb.KpDatabase.DeletedObjects)
                    {
                        tempDb.DeletedObjects.Add(del);
                    }
                }

                if (mainDb.KpDatabase.CustomIcons != null)
                {
                    foreach (var icon in mainDb.KpDatabase.CustomIcons)
                    {
                        tempDb.CustomIcons.Add(icon);
                    }
                }

                // Ensure root UUID matches so MergeIn finds the root (targetGroup)
                if (!pwDatabase.RootGroup.Uuid.Equals(targetGroup.Uuid))
                {
                    pwDatabase.RootGroup.Uuid = targetGroup.Uuid;
                }

                // Perform the merge
                tempDb.MergeIn(pwDatabase, PwMergeMethod.Synchronize);

                // Propagate changes back to mainDb
                // 1. Deleted Objects (MergeIn might have added new ones)
                // We assume deletions only accumulate.
                // Clear main list and copy back? Or just add missing?
                // Safest to rebuild main list from temp list to ensure we capture all updates
                if (mainDb.KpDatabase.DeletedObjects != null)
                {
                    mainDb.KpDatabase.DeletedObjects.Clear();
                    foreach (var del in tempDb.DeletedObjects)
                    {
                        mainDb.KpDatabase.DeletedObjects.Add(del);
                    }
                }

                // 2. Custom Icons
                if (mainDb.KpDatabase.CustomIcons != null)
                {
                    // tempDb.CustomIcons might have been modified (new icons added, unused removed if MergeIn did cleanup?)
                    // MergeInCustomIcons adds new icons. It doesn't seem to remove existing ones unless they are deleted?
                    // Let's copy back.
                    // Note: Since we are using List<T>, we can't just swap the reference safely if PwDatabase holds it differently
                    // (PwDatabase uses m_vCustomIcons field and exposes property).
                    // We must update the list in place.

                    // But wait, we populated tempDb.CustomIcons with clones? Or references?
                    // foreach (var icon in mainDb...) tempDb.CustomIcons.Add(icon);
                    // PwCustomIcon is a class. We added references.
                    // MergeIn might have replaced them with new objects or modified them.

                    // Safest to clear main and copy back.
                    mainDb.KpDatabase.CustomIcons.Clear();
                    foreach (var icon in tempDb.CustomIcons)
                    {
                        mainDb.KpDatabase.CustomIcons.Add(icon);
                    }

                    if (tempDb.UINeedsIconUpdate)
                        mainDb.KpDatabase.UINeedsIconUpdate = true;
                }

                // targetGroup itself is modified in-place because tempDb.RootGroup pointed to the SAME object instance.

                // Update globals
                mainDb.UpdateGlobals();

            }
            catch (Exception ex)
            {
                Kp2aLog.Log("KeeShare: Merge failed: " + ex.Message);
            }
        }

        private static IOConnectionInfo ResolvePath(IOConnectionInfo baseIoc, string path, IKp2aApp app)
        {
            var ioc = new IOConnectionInfo();
            ioc.Path = path;

            // Check if absolute
            if (path.StartsWith("/") || path.Contains("://"))
            {
                 if (!path.Contains("://"))
                 {
                     ioc.Path = path;
                     ioc.Plugin = "file";
                 }
                 return ioc;
            }

            // Relative path.
            try
            {
                string basePath = baseIoc.Path;
                string dir = Path.GetDirectoryName(basePath);
                string fullPath = Path.Combine(dir, path);
                ioc.Path = fullPath;
                ioc.Plugin = baseIoc.Plugin;
                ioc.UserName = baseIoc.UserName;
                ioc.Password = baseIoc.Password;
                return ioc;
            }
            catch
            {
                return null;
            }
        }
    }
}
