from django.shortcuts import render,redirect
from django.conf import settings
from django.contrib.auth.hashers import make_password
from passlib.hash import (pbkdf2_sha256, 
							pbkdf2_sha1, 
							sha256_crypt,
							sha1_crypt,
							md5_crypt,
							argon2,
						)
from django.contrib import messages

# Create your views here.

def home(request):
	return render(request, 'home.html')

def StringToHash(request):
	if request.method == "POST":
		raw_pass = request.POST.get('raw_pass')
		algo = request.POST.get('algorithm')
		rounds = request.POST.get('rounds', 0)
		raw_pass = str(raw_pass)

		if algo == 'pbkdf2_sha256':
			if rounds:
				hash_pass = pbkdf2_sha256.hash(raw_pass, rounds = rounds)
				_ ,_,rounds,salt, sha = hash_pass.split('$', 4)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt, 
														'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			# elif salt_size:
			# 	hash_pass = pbkdf2_sha256.hash(raw_pass, salt_size = salt_size)
			# 	_ ,_,rounds,salt, sha = hash_pass.split('$', 4)
			# 	return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt, 
			# 											'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			else:
				hash_pass = pbkdf2_sha256.hash(raw_pass)
				_ ,_,rounds,salt, sha = hash_pass.split('$', 4)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt, 
														'sha':sha, 'pass': raw_pass, 'algorithm': algo})

		elif algo == 'pbkdf2_sha1':
			if rounds:
				hash_pass = pbkdf2_sha1.hash(raw_pass, rounds = rounds)
				_ ,_,rounds,salt, sha = hash_pass.split('$', 4)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt,
					 									'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			# elif salt_size:
			# 	hash_pass = pbkdf2_sha1.hash(raw_pass, salt_size = salt_size)
			# 	_ ,_,rounds,salt, sha = hash_pass.split('$', 4)
			# 	return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt,
			# 		 									'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			else:
				hash_pass = pbkdf2_sha1.hash(raw_pass)
				_ ,_,rounds,salt, sha = hash_pass.split('$', 4)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt,
					 									'sha':sha, 'pass': raw_pass, 'algorithm': algo})

		elif algo == 'md5_crypt':
			# if salt_size:
			# 	hash_pass = md5_crypt.hash(raw_pass, salt_size = salt_size)
			# 	_,_,salt, sha = hash_pass.split('$', 3)
			# 	return render(request, 'hash.html', {'hash': hash_pass,'salt': salt, 
			# 											'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			# else:
			hash_pass = md5_crypt.hash(raw_pass)
			_,_,salt, sha = hash_pass.split('$', 3)
			return render(request, 'hash.html', {'hash': hash_pass,'salt': salt, 
													'sha':sha, 'pass': raw_pass, 'algorithm': algo})

		elif algo == 'sha256_crypt':
			if rounds:
				hash_pass = sha256_crypt.hash(raw_pass, rounds = rounds)
				_,_,rounds,salt, sha = hash_pass.split('$', 4)
				_,rods = rounds.split("=",2)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rods, 'salt':salt, 
														'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			# elif salt_size:
			# 	hash_pass = sha256_crypt.hash(raw_pass, salt_size = salt_size)
			# 	_,_,rounds,salt, sha = hash_pass.split('$', 4)
			# 	_,rods = rounds.split("=",2)
			# 	return render(request, 'hash.html', {'hash': hash_pass,'rounds': rods, 'salt':salt, 
			# 											'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			else:
				hash_pass = sha256_crypt.hash(raw_pass)
				_,_,rounds,salt, sha = hash_pass.split('$', 4)
				_,rods = rounds.split("=",2)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rods, 'salt':salt, 
														'sha':sha, 'pass': raw_pass, 'algorithm': algo})

		elif algo == 'sha1_crypt':
			if rounds:
				hash_pass = sha1_crypt.hash(raw_pass, rounds = rounds)
				_ ,_,rounds,salt,sha = hash_pass.split('$', 4)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt, 
														'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			# elif salt_size:
			# 	hash_pass = sha1_crypt.hash(raw_pass, salt_size = salt_size)
			# 	_ ,_,rounds,salt,sha = hash_pass.split('$', 4)
			# 	return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt, 
			# 											'sha':sha, 'pass': raw_pass, 'algorithm': algo})
			else:
				hash_pass = sha1_crypt.hash(raw_pass)
				_ ,_,rounds,salt,sha = hash_pass.split('$', 4)
				return render(request, 'hash.html', {'hash': hash_pass,'rounds': rounds, 'salt':salt, 
														'sha':sha, 'pass': raw_pass, 'algorithm': algo})

		elif algo == 'argon2':
			hash_pass = argon2.hash(raw_pass)
			_ ,_,_,_,salt,sha = hash_pass.split('$', 5)
			return render(request, 'hash.html', {'hash': hash_pass, 'salt':salt, 
													'sha':sha, 'pass': raw_pass, 'algorithm': algo})

		return render(request, 'string_to_hash.html')
	else:
		messages.info(request, "You cannot change the no. of iterations in 'md5_crypt' & 'argon2'")
		return render(request, 'string_to_hash.html')

