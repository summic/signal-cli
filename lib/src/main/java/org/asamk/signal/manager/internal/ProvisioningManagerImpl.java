/*
  Copyright (C) 2015-2022 AsamK and contributors

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.asamk.signal.manager.internal;

import org.asamk.signal.manager.Manager;
import org.asamk.signal.manager.ProvisioningManager;
import org.asamk.signal.manager.Settings;
import org.asamk.signal.manager.api.DeviceLinkUrl;
import org.asamk.signal.manager.api.UserAlreadyExistsException;
import org.asamk.signal.manager.config.ServiceConfig;
import org.asamk.signal.manager.config.ServiceEnvironmentConfig;
import org.asamk.signal.manager.storage.SignalAccount;
import org.asamk.signal.manager.storage.accounts.AccountsStore;
import org.asamk.signal.manager.util.KeyUtils;
import org.signal.core.models.AccountEntropyPool;
import org.signal.core.models.MasterKey;
import org.signal.core.models.ServiceId;
import org.signal.core.util.Hex;
import org.signal.core.util.UuidUtil;
import org.signal.core.models.backup.MediaRootBackupKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.util.ByteUtil;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.signalservice.api.push.ServiceIdType;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.AuthorizationFailedException;
import org.whispersystems.signalservice.api.registration.ProvisioningApi;
import org.whispersystems.signalservice.api.util.CredentialsProvider;
import org.whispersystems.signalservice.api.util.DeviceNameUtil;
import org.whispersystems.signalservice.internal.push.ProvisioningSocket;
import org.whispersystems.signalservice.internal.push.PushServiceSocket;
import org.whispersystems.signalservice.internal.util.DynamicCredentialsProvider;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.nio.channels.OverlappingFileLockException;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static org.asamk.signal.manager.util.KeyUtils.generatePreKeysForType;

public class ProvisioningManagerImpl implements ProvisioningManager {

    private static final Logger logger = LoggerFactory.getLogger(ProvisioningManagerImpl.class);

    private final PathConfig pathConfig;
    private final ServiceEnvironmentConfig serviceEnvironmentConfig;
    private final String userAgent;
    private final Consumer<Manager> newManagerListener;
    private final AccountsStore accountsStore;

    private final ProvisioningApi provisioningApi;
    private final ProvisioningSocket provisioningSocket;
    private final CredentialsProvider credentialsProvider;
    private final IdentityKeyPair tempIdentityKey;
    private final String password;

    public ProvisioningManagerImpl(
            PathConfig pathConfig,
            ServiceEnvironmentConfig serviceEnvironmentConfig,
            String userAgent,
            final Consumer<Manager> newManagerListener,
            final AccountsStore accountsStore
    ) {
        this.pathConfig = pathConfig;
        this.serviceEnvironmentConfig = serviceEnvironmentConfig;
        this.userAgent = userAgent;
        this.newManagerListener = newManagerListener;
        this.accountsStore = accountsStore;

        tempIdentityKey = KeyUtils.generateIdentityKeyPair();
        password = KeyUtils.createPassword();
        final var credentialsProvider = new DynamicCredentialsProvider(null,
                null,
                null,
                password,
                SignalServiceAddress.DEFAULT_DEVICE_ID);
        final var pushServiceSocket = new PushServiceSocket(serviceEnvironmentConfig.signalServiceConfiguration(),
                credentialsProvider,
                userAgent,
                ServiceConfig.AUTOMATIC_NETWORK_RETRY);
        final var provisioningSocket = new ProvisioningSocket(serviceEnvironmentConfig.signalServiceConfiguration(),
                userAgent);
        this.provisioningApi = new ProvisioningApi(pushServiceSocket, provisioningSocket, credentialsProvider);
        this.credentialsProvider = credentialsProvider;
        this.provisioningSocket = provisioningSocket;
    }

    @Override
    public URI getDeviceLinkUri() throws TimeoutException, IOException {
        var deviceUuid = provisioningApi.getNewDeviceUuid();

        return new DeviceLinkUrl(deviceUuid, tempIdentityKey.getPublicKey().getPublicKey()).createDeviceLinkUri();
    }

    @Override
    public String finishDeviceLink(String deviceName) throws IOException, TimeoutException, UserAlreadyExistsException {
        var ret = getNewDeviceRegistrationWithDebug();
        var number = ret.getNumber();
        var aci = ret.getAci();
        var pni = ret.getPni();

        logger.info("Received link information from {}, linking in progress ...", number);

        var accountPath = accountsStore.getPathByAci(aci);
        if (accountPath == null) {
            accountPath = accountsStore.getPathByNumber(number);
        }
        final var accountExists = accountPath != null && SignalAccount.accountFileExists(pathConfig.dataPath(),
                accountPath);
        if (accountExists && !canRelinkExistingAccount(accountPath)) {
            throw new UserAlreadyExistsException(number, SignalAccount.getFileName(pathConfig.dataPath(), accountPath));
        }
        if (accountPath == null) {
            accountPath = accountsStore.addAccount(number, aci);
        } else {
            accountsStore.updateAccount(accountPath, number, aci);
        }

        var encryptedDeviceName = deviceName == null
                ? null
                : DeviceNameUtil.encryptDeviceName(deviceName, ret.getAciIdentity().getPrivateKey());
        // Create new account with the synced identity
        var profileKey = ret.getProfileKey() == null ? KeyUtils.createProfileKey() : ret.getProfileKey();

        SignalAccount account = null;
        try {
            if (!accountExists) {
                account = SignalAccount.createLinkedAccount(pathConfig.dataPath(),
                        accountPath,
                        serviceEnvironmentConfig.type(),
                        Settings.DEFAULT);
            } else {
                account = SignalAccount.load(pathConfig.dataPath(), accountPath, true, Settings.DEFAULT);
            }

            account.setProvisioningData(number,
                    aci,
                    pni,
                    password,
                    encryptedDeviceName,
                    ret.getAciIdentity(),
                    ret.getPniIdentity(),
                    profileKey,
                    ret.getMasterKey(),
                    ret.getAccountEntropyPool(),
                    ret.getMediaRootBackupKey());

            account.getConfigurationStore().setReadReceipts(ret.isReadReceipts());

            final var aciPreKeys = generatePreKeysForType(account.getAccountData(ServiceIdType.ACI));
            final var pniPreKeys = generatePreKeysForType(account.getAccountData(ServiceIdType.PNI));

            logger.debug("Finishing new device registration");
            var deviceId = provisioningApi.finishNewDeviceRegistration(ret.getProvisioningCode(),
                    account.getAccountAttributes(null),
                    aciPreKeys,
                    pniPreKeys);
            logger.error("Linked device registration returned deviceId: {}", deviceId);

            account.finishLinking(deviceId, aciPreKeys, pniPreKeys);
            logger.error("Local account credentials after finishLinking: aci={}, pni={}, number={}, deviceId={}, passwordLength={}",
                    account.getAci(),
                    account.getPni(),
                    account.getNumber(),
                    account.getDeviceId(),
                    account.getPassword() == null ? -1 : account.getPassword().length());
            logger.error("Local account password fingerprint after finishLinking: {}", fingerprint(account.getPassword()));

            ManagerImpl m = null;
            try {
                m = new ManagerImpl(account,
                        pathConfig,
                        new AccountFileUpdaterImpl(accountsStore, accountPath),
                        serviceEnvironmentConfig,
                        userAgent);
                account = null;

                logger.debug("Refreshing pre keys");
                try {
                    m.refreshPreKeys();
                } catch (Exception e) {
                    logger.error("Failed to refresh pre keys.", e);
                }

                logger.debug("Requesting sync data");
                try {
                    m.requestAllSyncData();
                } catch (Exception e) {
                    logger.error(
                            "Failed to request sync messages from linked device, data can be requested again with `sendSyncRequest`.",
                            e);
                }

                if (newManagerListener != null) {
                    newManagerListener.accept(m);
                    m = null;
                }
                return number;
            } finally {
                if (m != null) {
                    m.close();
                }
            }
        } finally {
            if (account != null) {
                account.close();
            }
        }
    }

    private ProvisioningApi.NewDeviceRegistrationReturn getNewDeviceRegistrationWithDebug()
            throws IOException, TimeoutException {
        final var message = provisioningSocket.getProvisioningMessage(tempIdentityKey);
        logger.error("Provisioning message aci field: {}", message.aci);
        logger.error("Provisioning message pni field: {}", message.pni);
        logger.error("Provisioning message number field: {}", message.number);
        logger.error("Provisioning message provisioningVersion: {}", message.provisioningVersion);
        logger.error("Provisioning message aciBinary length: {}",
                message.aciBinary == null ? "null" : message.aciBinary.size());
        logger.error("Provisioning message pniBinary length: {}",
                message.pniBinary == null ? "null" : message.pniBinary.size());
        logger.error("Provisioning message aciBinary: {}",
                message.aciBinary == null ? "null" : Hex.toStringCondensed(message.aciBinary.toByteArray()));
        logger.error("Provisioning message pniBinary: {}",
                message.pniBinary == null ? "null" : Hex.toStringCondensed(message.pniBinary.toByteArray()));
        System.err.println("Provisioning message aci field: " + message.aci);
        System.err.println("Provisioning message pni field: " + message.pni);
        System.err.println("Provisioning message number field: " + message.number);
        System.err.println("Provisioning message provisioningVersion: " + message.provisioningVersion);
        System.err.println("Provisioning message aciBinary length: " + (message.aciBinary == null ? "null"
                : message.aciBinary.size()));
        System.err.println("Provisioning message pniBinary length: " + (message.pniBinary == null ? "null"
                : message.pniBinary.size()));
        System.err.println("Provisioning message aciBinary: "
                + (message.aciBinary == null ? "null" : Hex.toStringCondensed(message.aciBinary.toByteArray())));
        System.err.println("Provisioning message pniBinary: "
                + (message.pniBinary == null ? "null" : Hex.toStringCondensed(message.pniBinary.toByteArray())));

        var aci = parseServiceIdAci(message.aci, message.aciBinary);
        var pni = parseServiceIdPni(message.pni, message.pniBinary);
        if (credentialsProvider instanceof DynamicCredentialsProvider) {
            final var provider = (DynamicCredentialsProvider) credentialsProvider;
            provider.setAci(aci);
            provider.setPni(pni);
        }
        final var aciIdentity = parseIdentityKeyPair(message.aciIdentityKeyPublic.toByteArray(),
                message.aciIdentityKeyPrivate.toByteArray());
        final var pniIdentity = message.pniIdentityKeyPublic == null || message.pniIdentityKeyPrivate == null
                ? null
                : parseIdentityKeyPair(message.pniIdentityKeyPublic.toByteArray(), message.pniIdentityKeyPrivate.toByteArray());
        final ProfileKey profileKey;
        try {
            profileKey = message.profileKey == null ? null : new ProfileKey(message.profileKey.toByteArray());
        } catch (InvalidInputException e) {
            throw new IOException("Failed to decrypt profile key", e);
        }
        final MasterKey masterKey;
        try {
            masterKey = message.masterKey == null ? null : new MasterKey(message.masterKey.toByteArray());
        } catch (AssertionError e) {
            throw new IOException("Failed to decrypt master key", e);
        }
        final AccountEntropyPool accountEntropyPool = message.accountEntropyPool == null
                ? null
                : new AccountEntropyPool(message.accountEntropyPool);
        final MediaRootBackupKey mediaRootBackupKey = message.mediaRootBackupKey == null
                || message.mediaRootBackupKey.size() != 32 ? null : new MediaRootBackupKey(message.mediaRootBackupKey.toByteArray());
        if (credentialsProvider instanceof DynamicCredentialsProvider) {
            ((DynamicCredentialsProvider) credentialsProvider).setE164(message.number);
        }
        return createNewDeviceRegistrationReturn(message.provisioningCode,
                aciIdentity,
                pniIdentity,
                message.number,
                aci,
                pni,
                profileKey,
                masterKey,
                accountEntropyPool,
                mediaRootBackupKey,
                message.readReceipts != null && message.readReceipts);
    }

    private ProvisioningApi.NewDeviceRegistrationReturn createNewDeviceRegistrationReturn(
            String provisioningCode,
            IdentityKeyPair aciIdentity,
            IdentityKeyPair pniIdentity,
            String number,
            ServiceId.ACI aci,
            ServiceId.PNI pni,
            ProfileKey profileKey,
            MasterKey masterKey,
            AccountEntropyPool accountEntropyPool,
            MediaRootBackupKey mediaRootBackupKey,
            boolean readReceipts
    ) throws IOException {
        try {
            final var ctor = ProvisioningApi.NewDeviceRegistrationReturn.class.getDeclaredConstructor(
                    String.class,
                    IdentityKeyPair.class,
                    IdentityKeyPair.class,
                    String.class,
                    ServiceId.ACI.class,
                    ServiceId.PNI.class,
                    ProfileKey.class,
                    MasterKey.class,
                    AccountEntropyPool.class,
                    MediaRootBackupKey.class,
                    Boolean.TYPE);
            ctor.setAccessible(true);
            return (ProvisioningApi.NewDeviceRegistrationReturn) ctor.newInstance(provisioningCode,
                    aciIdentity,
                    pniIdentity,
                    number,
                    aci,
                    pni,
                    profileKey,
                    masterKey,
                    accountEntropyPool,
                    mediaRootBackupKey,
                    readReceipts);
        } catch (Exception e) {
            throw new IOException("Failed to parse provisioning return", e);
        }
    }

    private ServiceId.ACI parseServiceIdAci(final String aci, final okio.ByteString aciBinary) {
        if (aci != null) {
            return ServiceId.ACI.parseOrThrow(aci);
        }

        if (aciBinary != null && aciBinary.size() > 0) {
            final var rawBytes = aciBinary.toByteArray();
            final var parsed = parseServiceIdWithTypeMarker(rawBytes, true);
            if (parsed instanceof ServiceId.ACI) {
                return (ServiceId.ACI) parsed;
            }
        }

        throw new IllegalArgumentException("Invalid ACI!");
    }

    private ServiceId.PNI parseServiceIdPni(final String pni, final okio.ByteString pniBinary) {
        if (pni != null) {
            return ServiceId.PNI.parseOrThrow(pni);
        }

        if (pniBinary != null && pniBinary.size() > 0) {
            final var rawBytes = pniBinary.toByteArray();
            final var parsed = parseServiceIdWithTypeMarker(rawBytes, false);
            if (parsed instanceof ServiceId.PNI) {
                return (ServiceId.PNI) parsed;
            }
        }

        throw new IllegalArgumentException("Invalid PNI!");
    }

    private ServiceId parseServiceIdWithTypeMarker(final byte[] rawBytes, final boolean isAci) {
        if (rawBytes.length == 17) {
            final var parsed = ServiceId.Companion.parseOrNull(rawBytes);
            if (isAci && parsed instanceof ServiceId.ACI) {
                return parsed;
            }

            if (!isAci && parsed instanceof ServiceId.PNI) {
                return parsed;
            }

            if (parsed != null) {
                logger.error("Unexpected service id marker in {} bytes: {}", isAci ? "aci" : "pni",
                        parsed.getRawUuid());
            }
        }

        final var uuidBytes = rawBytes.length == 17 ? Arrays.copyOfRange(rawBytes, 1, rawBytes.length) : rawBytes;
        final var uuid = UuidUtil.INSTANCE.parseOrNull(uuidBytes);
        if (uuid != null) {
            return isAci ? ServiceId.ACI.from(uuid) : ServiceId.PNI.from(uuid);
        }

        if (rawBytes.length != 16 && rawBytes.length != 17) {
            throw new IllegalArgumentException("Invalid ServiceId binary length.");
        }

        throw new IllegalArgumentException("Invalid ServiceId binary.");
    }

    private IdentityKeyPair parseIdentityKeyPair(final byte[] publicKey, final byte[] privateKey) throws IOException {
        try {
            final byte[] fixedPublicKey = publicKey.length == 32
                    ? ByteUtil.combine(new byte[][] {new byte[] {0x05}, publicKey})
                    : publicKey;
            return new IdentityKeyPair(new IdentityKey(new ECPublicKey(fixedPublicKey)), new ECPrivateKey(privateKey));
        } catch (InvalidKeyException e) {
            throw new IOException("Failed to decrypt key", e);
        }
    }

    private boolean canRelinkExistingAccount(final String accountPath) throws IOException {
        final SignalAccount signalAccount;
        try {
            signalAccount = SignalAccount.load(pathConfig.dataPath(), accountPath, false, Settings.DEFAULT);
        } catch (IOException e) {
            logger.debug("Account in use or failed to load.", e);
            return false;
        } catch (OverlappingFileLockException e) {
            logger.debug("Account in use.", e);
            return false;
        }

        try (signalAccount) {
            if (signalAccount.isPrimaryDevice()) {
                logger.debug("Account is a primary device.");
                return false;
            }
            if (signalAccount.isRegistered()
                    && signalAccount.getServiceEnvironment() != null
                    && signalAccount.getServiceEnvironment() != serviceEnvironmentConfig.type()) {
                logger.debug("Account is registered in another environment: {}.",
                        signalAccount.getServiceEnvironment());
                return false;
            }

            final var m = new ManagerImpl(signalAccount,
                    pathConfig,
                    new AccountFileUpdaterImpl(accountsStore, accountPath),
                    serviceEnvironmentConfig,
                    userAgent);
            try (m) {
                m.checkAccountState();
            } catch (AuthorizationFailedException ignored) {
                return true;
            }

            logger.debug("Account is still successfully linked.");
            return false;
        }
    }

    private static String fingerprint(final String value) {
        if (value == null) {
            return "null";
        }
        try {
            final var digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            final int limit = Math.min(8, hash.length);
            final var sb = new StringBuilder(limit * 2);
            for (int i = 0; i < limit; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "fingerprint-error";
        }
    }
}
