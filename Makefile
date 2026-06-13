VM=ubuntu@10.104.28.103

sync:
	rsync -av --exclude .git --exclude .env ./ $(VM):~/protocol-sift-evals/

eval:
	ssh $(VM) 'cd ~/protocol-sift-evals && braintrust eval eval_protocol_sift.py'

test:
	cd scoring && python3 -m unittest discover -v
	cd trace_enrich && python3 -m unittest discover -v

manifests:
	ssh $(VM) 'find /home/ubuntu/Downloads -type f | sort' > dataset/manifest.txt
	ssh $(VM) 'hashdeep -r /home/ubuntu/Downloads' > dataset/hashes.txt

validate:
	python3 dataset/validate_cases.py
