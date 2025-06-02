package com.springboot.spring_hello.validator;

// interface tạo anotation custom cho Validation ngày sinh user 

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target({ ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR,
        ElementType.PARAMETER, ElementType.TYPE_USE }) // anotation đc sử dụng ở đâu
@Retention(RetentionPolicy.RUNTIME) // anotation đc xử lý lúc nào
@Constraint(validatedBy = {
    NgaySinhValidation.class
})
public @interface NgaySinhContraint {
    String message() default "USER_minBOB";

    int min();

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
