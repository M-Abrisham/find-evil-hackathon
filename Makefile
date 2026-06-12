VM=ubuntu@10.104.28.103

sync:
	rsync -av --exclude .git --exclude .env ./ $(VM):~/protocol-sift-evals/

eval:
	ssh $(VM) 'cd ~/protocol-sift-evals && braintrust eval eval_protocol_sift.py'

test:
	pytest -q

manifests:
	ssh $(VM) 'find /home/ubuntu/Downloads -type f | sort' > dataset/manifest.txt
	ssh $(VM) 'hashdeep -r /home/ubuntu/Downloads' > dataset/hashes.txt

validate:
	python3 dataset/validate_cases.py
