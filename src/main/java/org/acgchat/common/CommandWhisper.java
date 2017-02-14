package org.acgchat.common;

import org.acgchat.server.Server;

/**
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public class CommandWhisper implements Command {
    @Override
    public String getName() {
        return "/whisper";
    }

    @Override
    public String getShortHelp() {
        return "Message a user privately";
    }

    @Override
    public String[] getLongHelp() {
        return new String[]{"Usage: /whisper username message", getShortHelp()};
    }

    @Override
    public boolean execute(Server server, Server.ClientThread clientThread, String[] args) {
        String userToMsg = args[1];
        if(server.getLoggedIn().containsKey(userToMsg) && args.length >= 3){
           Server.ClientThread userToMsgThread = server.getUser(userToMsg);
           server.debug(userToMsgThread.getUser());
           userToMsgThread.writeMsg(new ChatMessage(ChatMessage.ChatMessageType.MESSAGE, "*Whisper*" + clientThread.getUser(), concatMsg(args)));
           return true;
        };
        return false;
    }

    public String concatMsg(String[] args){
        String msgToSend = "";
        for(int i = 2; i < args.length; i++ ){
            msgToSend = msgToSend + args[i] + " ";
        }
        return msgToSend;
    }

    @Override
    public boolean isAdminCommand() {
        return false;
    }
}
