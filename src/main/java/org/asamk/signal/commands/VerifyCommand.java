package org.asamk.signal.commands;

import com.fasterxml.jackson.core.type.TypeReference;

import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;

import org.asamk.signal.OutputType;
import org.asamk.signal.commands.exceptions.CommandException;
import org.asamk.signal.commands.exceptions.IOErrorException;
import org.asamk.signal.commands.exceptions.UserErrorException;
import org.asamk.signal.manager.RegistrationManager;
import org.asamk.signal.manager.api.IncorrectPinException;
import org.asamk.signal.manager.api.PinLockMissingException;
import org.asamk.signal.manager.api.PinLockedException;
import org.asamk.signal.output.JsonWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.SequencedCollection;

public class VerifyCommand implements RegistrationCommand, JsonRpcRegistrationCommand<VerifyCommand.VerifyParams> {

    private static final Logger logger = LoggerFactory.getLogger(VerifyCommand.class);

    @Override
    public String getName() {
        return "verify";
    }

    @Override
    public void attachToSubparser(final Subparser subparser) {
        subparser.help("Verify the number using the code received via SMS or voice.");
        subparser.addArgument("verification-code").nargs("?").help("The verification code you received via sms or voice call.");
        subparser.addArgument("-p", "--pin").help("The registration lock PIN, that was set by the user (Optional)");
        subparser.addArgument("--oauth")
                .help("Use OAuth login flow and skip SMS/voice code requirement.")
                .action(net.sourceforge.argparse4j.impl.Arguments.storeTrue());
    }

    @Override
    public void handleCommand(final Namespace ns, final RegistrationManager m) throws CommandException {
        var verificationCode = ns.getString("verification-code");
        var pin = ns.getString("pin");
        var oauthMode = ns.getBoolean("oauth") || isOAuthModeEnabled();

        if (oauthMode) {
            logger.info("OAuth mode enabled: skipping SMS/voice verification code enforcement.");
            if (verificationCode == null || verificationCode.isBlank()) {
                verificationCode = "000000";
            }
        }

        verify(m, verificationCode, pin);
    }

    @Override
    public TypeReference<VerifyParams> getRequestType() {
        return new TypeReference<>() {};
    }

    @Override
    public SequencedCollection<OutputType> getSupportedOutputTypes() {
        return List.of(OutputType.PLAIN_TEXT, OutputType.JSON);
    }

    @Override
    public void handleCommand(
            final VerifyParams request,
            final RegistrationManager m,
            final JsonWriter jsonWriter
    ) throws CommandException {
        var verificationCode = request.verificationCode();
        if (isOAuthModeEnabled() && (verificationCode == null || verificationCode.isBlank())) {
            verificationCode = "000000";
        }
        verify(m, verificationCode, request.pin());
    }

    private void verify(
            final RegistrationManager m,
            final String verificationCode,
            final String pin
    ) throws UserErrorException, IOErrorException {
        if (verificationCode == null || verificationCode.isBlank()) {
            throw new UserErrorException("Missing verification code. Provide one or use --oauth / SIGNAL_CLI_OAUTH_MODE=true.");
        }

        try {
            m.verifyAccount(verificationCode, pin);
        } catch (PinLockedException e) {
            throw new UserErrorException(
                    "Verification failed! This number is locked with a pin. Hours remaining until reset: "
                            + (e.getTimeRemaining() / 1000 / 60 / 60)
                            + "\nUse '--pin PIN_CODE' to specify the registration lock PIN");
        } catch (IncorrectPinException e) {
            throw new UserErrorException("Verification failed! Invalid pin, tries remaining: " + e.getTriesRemaining());
        } catch (PinLockMissingException e) {
            throw new UserErrorException("Account is pin locked, but pin data has been deleted on the server.");
        } catch (IOException e) {
            throw new IOErrorException("Verify error: " + e.getMessage(), e);
        }
    }

    private boolean isOAuthModeEnabled() {
        final var value = System.getenv("SIGNAL_CLI_OAUTH_MODE");
        return value != null && ("1".equals(value) || "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value));
    }

    public record VerifyParams(String verificationCode, String pin) {}
}
