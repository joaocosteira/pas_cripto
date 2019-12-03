make:
	mkdir -p keys
	python3 keyGenerator.py 2
	gnome-terminal -- sh -c "python3 Server.py; bash"
	gnome-terminal -- sh -c "python3 Client.py 0; bash"
	gnome-terminal -- sh -c "python3 Client.py 1; bash"

clean:
	rm __pycache__ -rf
	rm keys/*