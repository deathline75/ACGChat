package org.acgchat.common;

import java.io.Serializable;

/**
 * The ChatMessage object to be sent and received
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public class ChatMessage implements Serializable{

    private ChatMessageType type;
    private String user;
    private Object message;

    /**
     * Initialize the ChatMessage
     * @param type The type of message.
     * @param user The user associated with the message
     * @param message The message to send
     */
    public ChatMessage(ChatMessageType type, String user, Object message) {
        this.type = type;
        this.user = user;
        this.message = message;
    }

    /**
     * Get the type of chat message
     * @see ChatMessageType
     * @return The type of chat message
     */
    public ChatMessageType getType() {
        return type;
    }

    /**
     * Sets the type of chat message
     * @see ChatMessageType
     * @param type The type of chat message.
     */
    public void setType(ChatMessageType type) {
        this.type = type;
    }

    /**
     * Get the message sent
     * @return The message sent
     */
    public Object getMessage() {
        return message;
    }

    /**
     * Set the message sent
     * @param message The message to be sent
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Get the username that will send the message
     * @return the username that will send the message
     */
    public String getUser() {
        return user;
    }

    /**
     * Set the username that will send the message
     * @param user the username that will send the message
     */
    public void setUser(String user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return "ChatMessage{" +
                "type=" + type +
                ", user='" + user + '\'' +
                ", message=" + message +
                '}';
    }

    /**
     * This enumeration class is made to distinguish the different chat message types.
     */
    public enum ChatMessageType {
        /**
         * Regular Message
         */
        MESSAGE(0),
        /**
         * Logging into the server
         */
        LOGIN(1),
        /**
         * Registering in the server
         */
        REGISTER(2),
        /**
         * Log out of the server
         */
        LOGOUT(3),
        /**
         * Commands to send to the server
         */
        COMMAND(4),
        /**
         * Success message to the client
         */
        SUCCESS(10),
        /**
         * Error message to the client
         */
        ERROR(11);

        private int id;

        ChatMessageType(int id) {
            this.id = id;
        }

        /**
         * Get the ID of the message
         * @return the ID of the message
         */
        public int getId() {
            return id;
        }

        @Override
        public String toString() {
            return "ChatMessageType{" +
                    "id=" + id +
                    '}';
        }
    }

}
