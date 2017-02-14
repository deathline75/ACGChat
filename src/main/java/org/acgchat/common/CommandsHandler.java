package org.acgchat.common;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

/**
 * This class handles all the commands.
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public class CommandsHandler {

    private static HashMap<String, Command> commands = new HashMap<>();

    /**
     * Get the command based on the name
     * @param fullCommand The command
     * @return The {@link Command} that is linked to the string
     */
    public static Command getCommand(String fullCommand) {
        String first = fullCommand.split(" ")[0].toLowerCase();
        return commands.get(first);
    }

    /**
     * Get all the commands that are registered.
     * @return The commands that are registered.
     */
    public static Collection<Command> getCommands() {
        // The new HashSet is to make every entry unique.
        return new HashSet<>(commands.values());
    }

    static {
        // Registering all the commands
        CommandList commandList = new CommandList();
        commands.put("list", commandList);
        commands.put("whoisin", commandList);
        CommandWhisper commandWhisper = new CommandWhisper();
        commands.put("whisper", commandWhisper);
        CommandHelp commandHelp = new CommandHelp();
        commands.put("help", commandHelp);
    }

}
