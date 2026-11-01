import hashlib


def calculate_sha1(text) : 
    return hashlib.sha1(text.encode()).hexdigest()

message = input("Enter a message : ")

digest1 = calculate_sha1(message)

print("orignal Message : ")
print("sha digest : ",digest1)


#modify message sligtly
modified_mesage = message + "!"
digest2 = calculate_sha1(modified_mesage)

print("modified sha1 digest : ",digest2)

#compare 
if digest1 == digest2 : 
    print("message have the same digest")

else : 
    print("\nDigests differ: the input has changed.")

