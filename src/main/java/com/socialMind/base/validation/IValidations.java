package com.socialMind.base.validation;

import com.doc.easyschedulefeedback.base.enums.ValidationActionsEnum;
import com.doc.easyschedulefeedback.base.exception.Message;

import java.util.List;

public interface IValidations<MODEL> {
    void validate(MODEL data, ValidationActionsEnum action, List<Message> messagesToThrow);
}
