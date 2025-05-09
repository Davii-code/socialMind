package com.socialMind.base.exception;

import com.socialMind.base.enums.MessageCode;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;

@Getter
public class DataException extends RuntimeException {
    private final MessageResponse messageResponse;

    public DataException(MessageCode messageCode, HttpStatus status){
        super();
        messageResponse = new MessageResponse();
        messageResponse.setStatusCode(status.value());
        messageResponse.setMessages(new ArrayList<>());
        messageResponse.getMessages().add(new Message(messageCode));
    }


}
