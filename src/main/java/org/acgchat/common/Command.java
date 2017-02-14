package org.acgchat.common;

import org.acgchat.server.Server;

/**
 * The command object for execution
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public interface Command {

    /**
     * Get the name of the command
     * @return The name of the command
     */
    String getName();

    /**
     * Get the short help message for the command '/help'
     * @return The short help message
     */
    String getShortHelp();

    /**
     * Get the long help message for specific command.
     * eg. '/help list'
     * @return The long help message
     */
    String[] getLongHelp();

    /**
     * Execute the command
     * @param server The server handling the execution
     * @param clientThread The client that sent the command
     * @param args The arguments the client sent
     * @return Whether the execution was successful
     */
    boolean execute(Server server, Server.ClientThread clientThread, String[] args);

    /**
     * Check if the command is for administrators
     * @return Whether the command is for admins
     */
    boolean isAdminCommand();

}
