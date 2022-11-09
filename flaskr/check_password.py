# zdroj: https://www.geeksforgeeks.org/python-program-check-validity-password/

def check_password(password):
    lower, upper, special, digits = 0, 0, 0, 0
    if (len(password) >= 8):
        for i in password:
            # counting lowercase alphabets
            if (i.islower()):
                lower+=1           
    
            # counting uppercase alphabets
            if (i.isupper()):
                upper+=1           
    
            # counting digits
            if (i.isdigit()):
                digits+=1           
    
            # counting the mentioned special characters
            if(i=='@'or i=='$' or i=='_'):
                special+=1          
    return isPasswordValid(lower,upper,special,digits,password)

def isPasswordValid(lower,upper,special,digits,password):
    if(lower>=1 and upper>=1 and special>=1 and digits>=1 and lower+upper+special+digits==len(password)):
        return 1;        
    return 0;