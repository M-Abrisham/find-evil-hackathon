VM=ubuntu@10.104.28.103

sync:
	rsync -av --exclude .git --exclude .env ./ $(VM):~/protocol-sift-evals/

eval:
	ssh $(VM) 'cd ~/protocol-sift-evals && braintrust eval eval_protocol_sift.py'

test:
	pytest -q
