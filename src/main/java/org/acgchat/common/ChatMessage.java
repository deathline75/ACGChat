package org.acgchat.common;

/**
 * Created by Kelvin on 16/1/2017.
 */
public class ChatMessage {

    private ChatMessageType type;
    private String message;

    public ChatMessage(ChatMessageType type, String message) {
        this.type = type;
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

    public enum ChatMessageType {
        LOGIN(1),
        REGISTER(2),
        MESSAGE(0),
        COMMAND(3);

        private int id;

        ChatMessageType(int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }
    }

}
