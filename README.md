# AISpeechRecognitionPython

A simple command-line speech recognition tool. It listens through your microphone and prints what you said, using the SpeechRecognition library and PyAudio.

## Install

Install the two Python libraries.

    pip install SpeechRecognition pyaudio

On macOS, install PortAudio first with `brew install portaudio`.
On Linux (Debian or Ubuntu), install it first with `sudo apt install portaudio19-dev`.

## Run

    python SpeechRec.py

Speak when you see "Please say something..." and the text will print to the screen. An internet connection is required, since it uses Google's free speech-to-text service.
