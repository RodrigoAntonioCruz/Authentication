package br.com.appodontologia.validator;

import br.com.appodontologia.util.Constants;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UserConstraintValidator.class)
@Target(value = { ElementType.TYPE })
public @interface UserValidator {

    String message() default Constants.ERROR_VALIDATION;

    String value() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
