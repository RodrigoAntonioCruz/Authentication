package br.com.appodontologia.validator;

import br.com.appodontologia.domain.dto.users.request.SignupRequest;
import br.com.appodontologia.domain.enums.Roles;
import br.com.appodontologia.exception.FieldMessage;
import br.com.appodontologia.repository.UserRepository;
import br.com.appodontologia.util.Constants;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static br.com.appodontologia.util.Constants.PASSWORD_PATTERN;

@AllArgsConstructor
public class UserConstraintValidator implements ConstraintValidator<UserValidator, SignupRequest> {
    private final UserRepository userRepository;
    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

    @Override
    public void initialize(UserValidator ann) {
    }

    private boolean validPassword(String password) {
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

    private boolean getERole(SignupRequest request) {
        return Arrays.toString(Roles.values()).contains(request.getRoles().stream().findFirst().get());
    }

    @Override
    public boolean isValid(SignupRequest request, ConstraintValidatorContext context) {
        List<FieldMessage> list = new ArrayList<>();

        if (userRepository.existsByEmail(request.getEmail())) {
            list.add(new FieldMessage("email", Constants.MESSAGE_DUPLICATED_EMAIL));
        }

        if (!StringUtils.isEmpty(request.getPassword())) {
            if (!validPassword(request.getPassword())) {
                list.add(new FieldMessage("password", Constants.MESSAGE_INVALID_PASSWORD));
            }
        }

        if (!CollectionUtils.isEmpty(request.getRoles())){
            if (!getERole(request)) {
                list.add(new FieldMessage("roles", Constants.MESSAGE_INVALID_PROFILE));
            }
        }

        if (!StringUtils.isEmpty(request.getPassword())) {
            if (!request.getPassword().equals(request.getConfirm_password())) {
                list.add(new FieldMessage("confirm_password", Constants.MESSAGE_INVALID_PASSWORD_CONFIRM_NOT_EQUALS));
            }
        }

        list.forEach(e -> {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(e.getMessage()).addPropertyNode(e.getFieldName())
                    .addConstraintViolation();
        });

        return list.isEmpty();
    }
}
