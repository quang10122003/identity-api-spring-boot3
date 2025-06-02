package com.springboot.spring_hello.validator;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

// lớp xử lý cho anotation custom NgaySinhContraint
public class NgaySinhValidation implements ConstraintValidator<NgaySinhContraint,LocalDate> {

    private int min;
    @Override
    public boolean isValid(LocalDate value, ConstraintValidatorContext context) {
        if(Objects.isNull(value)){
            return true;    
        }
      Long years =  ChronoUnit.YEARS.between(value, LocalDate.now());
      if(years < min){
        return false;
      }else{
        return true;
      }
    }

    @Override
    public void initialize(NgaySinhContraint constraintAnnotation){
        ConstraintValidator.super.initialize(constraintAnnotation);
        min = constraintAnnotation.min();
    }
    
}
