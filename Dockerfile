# Download ubuntu from docker hub
FROM ubuntu:latest

# Download updates and install python3, pip and vim
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt-get install vim -y

# Declaring working directory to create directories and copy config files
WORKDIR /root
RUN mkdir -p .veracode
RUN mkdir -p .automation
COPY mypat .automation/
COPY credentials .veracode/

# Declaring working directory in our container
WORKDIR /opt/apps/python
RUN mkdir -p output
COPY requirements.txt .
COPY *.py .
COPY *.json .


# Install all requrements for our app
#RUN pip3 install -r requirements.txt
RUN pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

# Copy source files to $WORKDIR
# COPY . . 

# Expose container port to outside host
# EXPOSE 5000

# Run the application
CMD [ "python3", "main.py" ]