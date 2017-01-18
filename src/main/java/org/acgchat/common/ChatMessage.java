package org.acgchat.common;

/**
 * Created by Kelvin on 16/1/2017.
 */
public class ChatMessage {

    private ChatMessageType type;
    private String user;
    private String message;

    public ChatMessage(ChatMessageType type, String user, String message) {
        this.type = type;
        this.user = user;
        this.message = message;
    }

    public ChatMessageType getType() {
        return type;
    }

    public void setType(ChatMessageType type) {
        this.type = type;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public enum ChatMessageType {
        MESSAGE(0),
        LOGIN(1),
        REGISTER(2),
        LOGOUT(3),
        COMMAND(4);

        private int id;

        ChatMessageType(int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }
    }

}
