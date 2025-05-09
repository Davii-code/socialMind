package com.socialMind.base.validation;

import com.socialMind.base.enums.ValidationActionsEnum;
import com.socialMind.base.exception.Message;

import java.util.List;

public interface IValidations<MODEL> {
    void validate(MODEL data, ValidationActionsEnum action, List<Message> messagesToThrow);
}
