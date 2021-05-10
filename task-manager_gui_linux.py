import time
import os
from tkinter import *
interval=5.0
gui=Tk()
gui.configure(bg="black")
gui.title("MY TASK MANAGER")

intr_new=0
ctxt_new=0
def CPU():
	global cpu
	cpu=Tk()
	cpu.title("CPU Stats")
	cpu.configure(bg="orange")
	global mylistcpu	
	mylistcpu=Listbox(cpu,background="Orange")
	mylistcpu.config(width=100,height=100)
	CPU1()
def CPU1():
	mylistcpu.delete(0,END)
	cpub=Button(cpu,text="Back",bg="orange",width=20,command=cpu.destroy)
	cpub.pack()
	readCPU= open("/proc/stat","r").read();
	data1= readCPU.split("\n");
	cpuCount=0
	for word in data1:
		if word.find("cpu")!=-1:
			cpuCount+=1
	mylistcpu.insert(END,("No. of Cpu's are:",(cpuCount-1)))
	mylistcpu.insert(END," ")
	mylistcpu.insert(END,("CPU and system Statistics:::::::::::::::::"))
	mylistcpu.insert(END," ")
	user_old=0
	sys_old=0
	idle_old=0
	user_new=0
	sys_new=0
	idle_new=0
	global intr_new
	global ctxt_new
	#while(1<2):
	readCPU=open("/proc/stat","r").read();
	data1=readCPU.split("\n");
	i=0
	while(i<cpuCount):
		user_old=0
		sys_old=0
		idle_old=0
		user_new=0
		sys_new=0
		idle_new=0
		cpu_info=data1[i].split()
		#print(cpu_info)
		mylistcpu.insert(END," ")		
		mylistcpu.insert(END,(cpu_info[0],"::::::"))
		
		user_old=user_new
		user_new=float(cpu_info[1])/100
		#print(user_new)	
		sys_old=sys_new
		sys_new=float(cpu_info[3])/100
		#print(sys_new)
		idle_old=idle_new
		idle_new=float(cpu_info[4])/100
		#print(idle_new)
		u_mode=user_new-user_old
		#print(u_mode)
		s_mode=sys_new-sys_old
		#print(s_mode)
		i_mode=idle_new-idle_old
		#print(i_mode)
		userUtilization=(float(u_mode)/(u_mode+s_mode+i_mode))*100
		sysUtilization=(float(s_mode)/(u_mode+s_mode+i_mode))*100
		cpuUtilization=(float(u_mode+s_mode)/(u_mode+s_mode+i_mode))*100
		mylistcpu.insert(END,("UserMode CPU utilization for",cpu_info[0],"is",userUtilization))
		mylistcpu.insert(END,("SystemMode CPU utilization for",cpu_info[0],"is",sysUtilization))
		mylistcpu.insert(END,("Overall CPU utilization for",cpu_info[0],"is",cpuUtilization))	
		i=i+1
		 
#while(1<2):
	
	i=0
	while(i<len(data1)):
		if data1[i].startswith("intr"):
			intr=data1[i].split()
			#print(intr)
			intr_old=float(intr_new)
			intr_new=float(intr[1])
			mylistcpu.insert(END," ")
			mylistcpu.insert(END,("The number of interrupts is:",float(intr_new-intr_old)/interval))		
		if data1[i].startswith("ctxt"):
			ctxt=data1[i].split()
			#print(ctxt)
			ctxt_old=float(ctxt_new)
			ctxt_new=float(ctxt[1])
			mylistcpu.insert(END,("The number of context switches is:",float(ctxt_new-ctxt_old)/interval))
			mylistcpu.insert(END," ")
		i+=1
	mylistcpu.insert(END,("Memory Statistics:::::::::::::::::::::"))
	pre_freemem=0
	cur_freemem=0
	total_mem=0
	free_mem=0
	#while(1<2):
	readMem=open("/proc/meminfo","r").read();	
	data2= readMem.split("\n");
	t_m=data2[0].split()
	#print(t_m)
	c_m=data2[1].split()
	#print(c_m)
	pre_freemem=cur_freemem
	cur_freemem=float(c_m[1])/1024
	total_mem=float(t_m[1])/1024
	free_mem=(float)(pre_freemem+cur_freemem)/2 
	total_memUtil= ((float)(total_mem-free_mem)/(float)(total_mem))*100
	mylistcpu.insert(END,("Total Memory is",total_mem,"MB"))
	mylistcpu.insert(END,("Available Memory is",free_mem,"MB"))
	mylistcpu.insert(END,("Memory Utilization is",total_memUtil,"%"))
	mylistcpu.pack(side=LEFT,fill=BOTH)
	cpub=Button(cpu,text="Back",width=25,command=cpu.destroy)
	cpub.pack()
	cpu.after(4000,CPU1)
	



diskwrite_old=0
diskwrite_new=0
sectorwrite_old=0
sectorwrite_new=0
disksubwrite_old=0
disksubwrite_new=0
sectorsubwrite_old=0
sectorsubwrite_new=0		
def DISK():
	global disk
	disk=Tk()
	disk.title("DISK Stats")
	disk.configure(bg="orange")
	global mylistdisk
	mylistdisk=Listbox(disk,background="Orange")
	mylistdisk.config(width=100,height=100)
	DISK1()
def DISK1():
	mylistdisk.delete(0,END)
	diskb=Button(disk,text="Back",bg="orange",width=20,command=disk.destroy)
	diskb.pack()
	readDisk=open("/proc/diskstats","r").read()
	data3= readDisk.split("\n")
	sdaCount=0
	for word in data3:
		if word.find("sd")!=-1:
			sdaCount+=1
	mylistdisk.insert(END,("No. of sd's are:",(sdaCount)))
	mylistdisk.insert(END,("\nDisk i/o Statistics:::::::::::::"))
	diskread_old=0
	global diskwrite_old
	diskread_new=0
	global diskwrite_new
	sectorread_old=0
	global sectorwrite_old
	sectorread_new=0
	global sectorwrite_new
	disksubread_old=0
	global disksubwrite_old
	disksubread_new=0
	global disksubwrite_new
	sectorsubread_old=0
	global sectorsubwrite_old
	sectorsubread_new=0
	global sectorsubwrite_new
	readDisk=open("/proc/diskstats","r").read();
	data3= readDisk.split();
	q=1
	while(q<sdaCount):
		sdaIndex=data3.index("sda")
		if(sdaCount>1):
			sdasubIndex=data3.index("sda"+str(sdaCount-1))
			sdaCount-=1	
		diskread_old=diskread_new
		diskwrite_old=diskwrite_new
		sectorread_old=sectorread_new
		sectorwrite_old=sectorwrite_new
		diskread_new=float(data3[sdaIndex+1])
		diskwrite_new=float(data3[sdaIndex+5])
		sectorread_new=float(data3[sdaIndex+3])
		sectorwrite_new=float(data3[sdaIndex+7])
		disksubread_old=disksubread_new
		disksubwrite_old=disksubwrite_new
		sectorsubread_old=sectorsubread_new
		sectorsubwrite_old=sectorsubwrite_new
		disksubread_new=float(data3[sdasubIndex+1])
		disksubwrite_new=float(data3[sdasubIndex+5])
		sectorsubread_new=float(data3[sdasubIndex+3])
		sectorsubwrite_new=float(data3[sdasubIndex+7])
		mylistdisk.insert(END,(data3[sdaIndex],"data::::"))		
		diskread_int=float(diskread_new-diskread_old)/5.0
		mylistdisk.insert(END,("Number of Diskreads:",diskread_int))
		diskwrite_int=float(diskwrite_new-diskwrite_old)/5.0
		mylistdisk.insert(END,("Number of diskwrites:",diskwrite_int))
		sectorread_int=float(sectorread_new-sectorread_old)/5.0
		mylistdisk.insert(END,("Number of Sectorreads:",sectorread_int))
		sectorwrite_int=float(sectorwrite_new-sectorwrite_old)/5.0
		mylistdisk.insert(END,("Number of sectorwrites:",sectorwrite_int))
		mylistdisk.insert(END,(data3[sdasubIndex],"data::::"))
		disksubread_int=float(disksubread_new-disksubread_old)/5.0
		mylistdisk.insert(END,("Number of Diskreads:",disksubread_int))
		disksubwrite_int=float(disksubwrite_new-disksubwrite_old)/5.0
		mylistdisk.insert(END,("Number of diskwrites:",disksubwrite_int))
		sectorsubread_int=float(sectorsubread_new-sectorsubread_old)/5.0
		mylistdisk.insert(END,("Number of Sectorreads:",sectorsubread_int))
		sectorsubwrite_int=float(sectorsubwrite_new-sectorsubwrite_old)/5.0
		mylistdisk.insert(END,("Number of sectorwrites:",sectorsubwrite_int))
		q+=1		
	mylistdisk.pack(side=LEFT,fill=BOTH)	
	disk.after(4000,DISK1)

def NET():
	global net
	net=Tk()	
	net.title("NETWORK Stats")
	net.configure(bg="orange")
	global scrollbartcp
	scrollbartcp=Scrollbar(net)
	scrollbartcp.pack(side=RIGHT,fill=Y)
	global mylisttcp
	mylisttcp=Listbox(net,yscrollcommand=scrollbartcp.set,background="Orange")
	mylisttcp.config(width=100,height=0)
	net.geometry("5000x5000")
	NET1()
def NET1():
	mylisttcp.delete(0,END)
	netb=Button(net,text="Back",bg="orange",width=20,command=net.destroy)
	netb.pack()
	read=open("/proc/net/dev","r").read()
	data=read.split("\n")
	#print(data)
	#print(len(data))
	i=2
	while(i<len(data)-1):
		try:
			netu=data[i].split()
			#print(net)
			received_bytes=int(netu[1])/1000000
			#print(received_bytes)
			transmitted_bytes=int(netu[9])/1000000
			#print(transmitted_bytes)
			reads=os.popen("sudo ethtool %s| grep -i speed"%(netu[0])).read()
			#print(reads)
			datas=reads.split(":")
			#print(datas)
			bandwidth=datas[1]
			#print(bandwidth)
			bandwidth=float(bandwidth[bandwidth.find("%d")	+1:bandwidth.find("M")])
			#print(bandwidth)
			networkUtilization=float(received_bytes+transmitted_bytes)/	bandwidth
			mylisttcp.insert(END,("Network Utilization for",netu[0],"is:",networkUtilization))
			mylisttcp.insert(END,(" "))
		except IndexError:
			fveogbnvs=0
		i+=1
	readconntcp=open("/proc/net/tcp","r").read();
	#print(readconntcp)
	datatcp=readconntcp.split("\n")
	#print(datatcp)
	i=1
	count=0
	while(i<len(datatcp)-1):
		tcp_conn=datatcp[i].split()
		#print(tcp_conn)
		if((tcp_conn[3])=='01'):
			count+=1
		i+=1
	mylisttcp.insert(END,("Total number of TCP connections active are:",len(datatcp)-2))
	mylisttcp.insert(END,("Total number of TCP connections established are:",count))
	readconnudp=open("/proc/net/udp","r").read();
	#print(readconnudp)
	dataudp=readconnudp.split("\n")
	#print(dataudp)
	mylisttcp.insert(END,("Total number of UDP connections active are:",len(dataudp)-2))
	###END OF THIS########
	###Source addr,Destination addr,UserName from TCP

	readtcp=open("/proc/net/tcp","r").read()
	#print(readtcp)
	readudp=open("/proc/net/udp","r").read()
	#print(readudp)
	datatcp=readtcp.split("\n")
	#print(datatcp)
	dataudp=readudp.split("\n")
	#print(dataudp)
	#####local and remote addr in IP format
	readps=os.listdir("/proc")
	#print(readps)
	for j in range(0,len(readps)):
			try:
				readps[j]=int(readps[j])
				#print(readps[j])
			except FileNotFoundError as e:
				u=2			
				#print("ERROR: %s"%e)
			except ValueError:
				p=2
				#print(readps[j],"is not a directory")
	#print(readps)
	readtcp=open("/proc/net/tcp","r").read()
	#print(readtcp)
	readudp=open("/proc/net/udp","r").read()
	#print(readudp)
	datatcp=readtcp.split("\n")
	#print(datatcp)
	dataudp=readudp.split("\n")
	#print(dataudp)
	#####local and remote addr in IP format
	i=1
	while(i<len(datatcp)-1):
		tcp=datatcp[i].split()
		#print(tcp)
		localaddrtcp=tcp[1].split(":")
		#print(localaddrtcp)
		remoteaddrtcp=tcp[2].split(":")
		#print(remoteaddrtcp)
		mylisttcp.insert(END," ")
		mylisttcp.insert(END,("TCP connection:",tcp[0],"::::::::::"))
		#########username from uid#####	
		uidtcp=tcp[7]
		findusertcp=open("/etc/passwd","r").read()
		#print(findusertcp)
		finduserdatatcp=findusertcp.split()
		#print(finduserdatatcp)
		u=0
		while(u<len(finduserdatatcp)):
			try:
				userinfotcp=finduserdatatcp[u].split(":")
				#print(userinfotcp)
				if(uidtcp==userinfotcp[2]):
					mylisttcp.insert(END,("Name of the User accessing TCP connection",tcp[0],"is:",userinfotcp[0]))
					w=0
			except IndexError:
				a=2
			u+=1	
		i+=1
		ip_localaddrtcp="%i.%i.%i.%i"%(int(localaddrtcp[0][0:2],16),int(localaddrtcp[0][2:4],16),int(localaddrtcp[0][4:6],16),int(localaddrtcp[0][6:8],16))
		mylisttcp.insert(END,("Source address of TCP connection",tcp[0],"is:",ip_localaddrtcp))
		ip_remoteaddrtcp="%i.%i.%i.%i"%(int(remoteaddrtcp[0][0:2],16),int(remoteaddrtcp[0][2:4],16),int(remoteaddrtcp[0][4:6],16),int(remoteaddrtcp[0][6:8],16))
		mylisttcp.insert(END,("Destination address of TCP connection",tcp[0],"is:",ip_remoteaddrtcp))
	#### Program name from inode####
		inode=int(tcp[9])
		#print(inode)
		for j in range(0,len(readps)):
			try:
				readps[j]=int(readps[j])
				#print(readps[j])
			except FileNotFoundError as e:
				nouse=0
			except ValueError:
				nouse1=0
		#f=os.system("sudo -i")
		for j in range(0,len(readps)):
			try:
				read2=os.listdir("/proc/%d/fd"%(readps[j]))
				#print("for process ",readps[j],"::")
				read3=os.popen("ls -l /proc/%d/fd"%(readps[j])).read()
				#print(read3)
				data3=read3.split("\n")
				#print(data3)
				k=1
				while(k<len(data3)):
					try:
						everyfile=data3[k].split()
						#print(everyfile)
						k+=1
						socpipe=everyfile[10].split(":")
						#print(socpipe)
						socpipenum=socpipe[1]
						socpipenum=socpipenum[socpipenum.find("[")+1:socpipenum.find("]")]
						#print(socpipenum)
						if(inode==int(socpipenum)):
							#print("process",readps[j])
							readpidinfo=open("/proc/%d/stat"%readps[j],"r").read()
							datapid=readpidinfo.split("\n")
							#print(datapid)
							everypid=datapid[0].split()
							mylisttcp.insert(END,("Name of process accessing TCP connection ",tcp[0],"is:",everypid[1]))
						else:			
							hyg=0		
					except ValueError:
						hgf=0
					except IndexError:
						ind=0		
			except FileNotFoundError:
				fdgt=0
			except TypeError:
				fgr=0

	######UDP#####
	i=1
	while(i<len(dataudp)-1):
		udp=dataudp[i].split()
		#print(udp)
		localaddrudp=udp[1].split(":")
		#print(localaddrudp)
		remoteaddrudp=udp[2].split(":")
		#print(remoteaddrudp)
		mylisttcp.insert(END," ")
		mylisttcp.insert(END,("UDP connection",udp[0],":::::::::"))
	##local and remote address####
		######username####
		uidudp=udp[7]
		finduserudp=open("/etc/passwd","r").read()
		#print(finduserudp)
		finduserdataudp=finduserudp.split()
		#print(finduserdataudp)
		u=0
		while(u<len(finduserdataudp)):
			try:
				userinfoudp=finduserdataudp[u].split(":")
				#print(userinfoudp)
				if(uidudp==userinfoudp[2]):
					mylisttcp.insert(END,("Name of the User accessing UDP connection",udp[0],"is:",userinfoudp[0]))		
			except IndexError:
				a=2
			u+=1		
		ip_localaddrudp="%i.%i.%i.%i"%(int(localaddrudp[0][0:2],16),int(localaddrudp[0][2:4],16),int(localaddrudp[0][4:6],16),int(localaddrudp[0][6:8],16))
		mylisttcp.insert(END,("Source address of UDP connection",udp[0],"is:",ip_localaddrudp))
		ip_remoteaddrudp="%i.%i.%i.%i"%(int(remoteaddrudp[0][0:2],16),int(remoteaddrudp[0][2:4],16),int(remoteaddrudp[0][4:6],16),int(remoteaddrudp[0][6:8],16))
		mylisttcp.insert(END,("Destination address of UDP connection",udp[0],"is:",ip_remoteaddrudp))
		i+=1
	####program from inode#####
		inode=int(udp[9])
		#print(inode)
		for j in range(0,len(readps)):
			try:
				readps[j]=int(readps[j])
				#print(readps[j])
			except FileNotFoundError as e:
				nouse=0
			except ValueError:
				nouse1=0
		#f=os.system("sudo -i")
		for j in range(0,len(readps)):
			try:
				read2=os.listdir("/proc/%d/fd"%(readps[j]))
				#print("for process ",readps[j],"::")
				read3=os.popen("ls -l /proc/%d/fd"%(readps[j])).read()
				#print(read3)
				data3=read3.split("\n")
				#print(data3)
				k=1
				while(k<len(data3)):
					try:
						everyfile=data3[k].split()
						#print(everyfile)
						k+=1
						socpipe=everyfile[10].split(":")
						#print(socpipe)
						socpipenum=socpipe[1]
						socpipenum=socpipenum[socpipenum.find("[")+1:socpipenum.find("]")]
						#print(socpipenum)
						if(inode==int(socpipenum)):
							#print("process",readps[j])
							readpidinfo=open("/proc/%d/stat"%readps[j],"r").read()
							datapid=readpidinfo.split("\n")
							#print(datapid)
							everypid=datapid[0].split()
							mylisttcp.insert(END,("Name of process accessing UDP connection ",udp[0],"is:",everypid[1]))
						else:			
							hyg=0	
					except ValueError:
						hgf=0
					except IndexError:
						ind=0
			except FileNotFoundError:
				fgrrd=0
			except TypeError:
				fgr=0
	mylisttcp.pack(side=LEFT,fill=BOTH)
	scrollbartcp.config(command=mylisttcp.yview)
	net.after(4000,NET1)	
	


def PROC():
	global proc
	proc=Tk()
	proc.title("PROCESS STATS")
	proc.configure(bg="orange")
	global scrollbarproc
	scrollbarproc=Scrollbar(proc)
	scrollbarproc.pack(side=RIGHT,fill=Y)
	global mylistproc	
	mylistproc=Listbox(proc,yscrollcommand=scrollbarproc.set,background="Orange")
	mylistproc.config(width=100,height=0)
	PROC1()
def PROC1():
	mylistproc.delete(0,END)
	procb=Button(proc,text="Back",bg="orange",width=20,command=proc.destroy)
	procb.pack()
	readps=os.listdir("/proc")
	#print(readps)
	#print(len(readps))
	user_old=0
	sys_old=0
	idle_old=0
	user_new=0
	sys_new=0
	idle_new=0
	readCPU= open("/proc/stat","r").read();
	#print(readCPU)
	data1= readCPU.split("\n");
	#print(data1)
	readCPU= open("/proc/stat","r").read();
	#print(readCPU)
	data1= readCPU.split("\n");
	cpuCount=0
	for word in data1:
		if word.find("cpu")!=-1:
			cpuCount+=1
	#print("No. of Cpu's are:",(cpuCount-1))
	readCPU=open("/proc/stat","r").read();
	data1=readCPU.split("\n");
	i=0
	while(i<cpuCount-1):
		user_old=0
		sys_old=0
		idle_old=0
		user_new=0
		sys_new=0
		idle_new=0
		cpu_info=data1[i].split()
		mylistproc.insert(END,("With ",cpu_info[0],":::::::::::::::::"))	
		mylistproc.insert(END," ")
		user_old=user_new
		user_new=float(cpu_info[1])/100
		#print(user_new)	
		sys_old=sys_new
		sys_new=float(cpu_info[3])/100
		#print(sys_new)
		idle_old=idle_new
		idle_new=float(cpu_info[4])/100
		#print(idle_new)
		u_mode=user_new-user_old
		#print(u_mode)
		s_mode=sys_new-sys_old
		#print(s_mode)
		i_mode=idle_new-idle_old
		#print(i_mode)
		interval=float(u_mode+s_mode+i_mode)
		for j in range(0,len(readps)):
			try:
				readps[j]=int(readps[j])
				#print(readps[j])	
				readpidinfo=open("/proc/%d/stat"%readps[j],"r").read()
				datapid=readpidinfo.split("\n")
				#print(datapid)
				everypid=datapid[0].split()
				#print(everypid)
				mylistproc.insert(END,("Process",everypid[0],everypid[1],":::::::"))
				userp_time=float(everypid[13])
				sysp_time=float(everypid[14])
				overallp_time=float(everypid[13]+everypid[14])
				#print(userp_time)
				#print(sysp_time)
				#print(overallp_time)
				userP_util=float(userp_time/interval)
				sysP_util=float(sysp_time/interval)
				overallP_util=float(overallp_time/interval)
				mylistproc.insert(END,("Usermode Utilization for process",everypid[0],"is",userP_util))
				mylistproc.insert(END,("Systemmode Utilization for process",everypid[0],"is",sysP_util))
				mylistproc.insert(END,("Overall Utilization for process",everypid[0],"is",overallP_util))
				readMem=open("/proc/meminfo","r").read();
				data2= readMem.split("\n");
				t_m=data2[0].split()
				#print(t_m)
				user_vsize=(float(everypid[22])/1000)/float(t_m[1])
				mylistproc.insert(END,("Virtual memory Utilization for",everypid[0],"is %.8f"%user_vsize))
				user_rss=(float(everypid[23])/128)/float(t_m[1])
				mylistproc.insert(END,("Physical memory Utilization for",everypid[0],"is %.8f"%user_rss))
				readuid=open("/proc/%s/status"%everypid[0],"r").read()
				datauid=readuid.split("\n")
				useruid=datauid[8].split()
				uid=useruid[1]
				#print(uid)
				finduser=open("/etc/passwd","r").read()
				finduserdata=finduser.split()
				#print(finduserdata)
				u=0
				while(u<len(finduserdata)):
					try:
						userinfo=finduserdata[u].split(":")
						#print(userinfo)
						if(uid==userinfo[2]):
							mylistproc.insert(END,("Name of the User accessing process",everypid[0],everypid[1],"is:",userinfo[0]))		
					except IndexError:
						a=2
					u+=1	
				mylistproc.insert(END,("Name of the process",everypid[0],"is:",everypid[1]))
			except FileNotFoundError as e:
				drc=0				
				#print("ERROR: %s"%e)
			except ValueError:
				ow=0
				#print(readps[j],"is not a directory")
			j+=1
		mylistproc.insert(END,(" "))
		i+=1
	mylistproc.pack(side=LEFT,fill=BOTH)
	scrollbarproc.config(command=mylistproc.yview)	
	proc.after(4000,PROC1)

			

bcpu=Button(gui,text="CPU and MEMORY STATS",bg="orange",fg="black",width=30,command=CPU)
bcpu.pack()
bdisk=Button(gui,text="DISK STATS",bg="orange",fg="black",width=30,command=DISK)
bdisk.pack()
bnet=Button(gui,text="NETWORK STATS",bg="orange",fg="black",width=30,command=NET)
bnet.pack()
bproc=Button(gui,text="PROCESS STATS",bg="orange",fg="black",width=30,command=PROC)
bproc.pack()
name=Label(gui,text="Developed by NITEESH REDDY THOTA",fg="red",bg="black",font="Bahnschrift")
name.pack()


gui.mainloop()
