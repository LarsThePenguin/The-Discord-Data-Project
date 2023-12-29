########################
# Discord Data Project #
########################
# Current build: 0.1
# Issue: It chrashes when reading a file.

from winfspy import FileSystem, enable_debug_log
import discord, pickle, asyncio
from winfspy.memfs import *
import threading, time, os
from textwrap import wrap

TOKEN = input("Enter Discord Token: ")
try:
  CHANNEL_ID = int(input("Enter Channel ID: "))
except:
  print("The channel ID should be an integer");exit(1)

client = discord.Client(intents=discord.Intents.default(), max_messages=500)
global channel
backslash = "\\"
maxFileSize = 20_000_000

currentWriteSpeed = 0
printCurrentWriteSpeed = False
currentReadSpeed = 0
printCurrentReadSpeed = False

def addToReadSpeed(numb):
	global currentReadSpeed, printCurrentReadSpeed
	currentReadSpeed += numb
	printCurrentReadSpeed = True

def addToWriteSpeed(numb):
	global currentWriteSpeed, printCurrentWriteSpeed
	currentWriteSpeed += numb
	printCurrentWriteSpeed = True

async def asyncListToList(asyncList) -> list:
	return [gen async for gen in asyncList]

def strToBytearray(string: str) -> bytearray:
	returnVal = bytearray(len(string))
	for i in range(len(string)):
		returnVal[i] = string[i]
	return returnVal

def runAsyncFunction(func):
	task = client.loop.create_task(func)
	while not task.done():
		pass
	result = task.result()
	return result

def macroForPickle(self):
	try:
		with open("files.pickle", "rb") as fr:
			stuff = pickle.load(fr)
			stuff[str(self.pathForSaving)] = [self.attributesForSaving, self.securityDescriptorForSaving.to_string(), self.IDs]
			with open("files.pickle", "wb") as fw:
				pickle.dump(stuff, fw)
	except EOFError:
			stuff = {}
			stuff[str(self.pathForSaving)] = [self.attributesForSaving, self.securityDescriptorForSaving.to_string(), self.IDs]
			with open("files.pickle", "wb") as fw: 
				pickle.dump(stuff, fw)

def readFile(listOfMessageIDs: list) -> bytearray:
	messages = runAsyncFunction(asyncListToList(channel.history(limit=46116000000)))
	returnData = bytearray(0)
	for message in messages:
		if message.id in listOfMessageIDs:
			for i in message.attachments:
				currentData = runAsyncFunction(i.read())
				returnData += currentData
	return returnData

def uploadFile(data: bytearray) -> list:
	startTime = time.time()
	chunks = wrap(data.decode("latin-1"), maxFileSize)
	messageIDs = []
	for chunk in chunks:
		file = open("upldchk.tmp.txt", "wb")
		file.write(bytes(chunk, encoding="latin-1"))
		file.close()
		message = runAsyncFunction(channel.send(file=discord.File("upldchk.tmp.txt")))
		messageIDs.append(message.id)
		os.remove("upldchk.tmp.txt")
	addToWriteSpeed(len(data)/(time.time() - startTime))
	return messageIDs

class DiscordFile(BaseFileObj):

	allocation_unit = 4096

	def __init__(self, path, attributes, security_descriptor, allocation_size=0):
		super().__init__(path, attributes, security_descriptor)
		self.IDs = []
		self.attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE
		self.isCached = False
		self.cacheLastAccess = 0
		self.pathForSaving = path
		self.attributesForSaving = attributes
		self.securityDescriptorForSaving = security_descriptor
		macroForPickle(self)

	@property
	def allocation_size(self):
		return self.file_size
	
	def set_allocation_size(self, allocation_size):
		if allocation_size < self.allocation_size:
			data = readFile(self.IDs)
			data = data[:allocation_size]
			self.IDs = uploadFile(data)
			macroForPickle(self)
		if allocation_size > self.allocation_size:
			data = readFile(self.IDs)
			data += bytearray(allocation_size - self.allocation_size)
			self.IDs = uploadFile(data)
		macroForPickle(self)
		self.file_size = min(self.file_size, allocation_size)

	def adapt_allocation_size(self, file_size):
		units = (file_size + self.allocation_unit - 1) // self.allocation_unit
		self.set_allocation_size(units * self.allocation_unit)

	def set_file_size(self, file_size):
		if file_size < self.file_size:
			zeros = bytearray(self.file_size - file_size)
			data = readFile(self.IDs)
			data[file_size:self.file_size] = zeros
			self.IDs = uploadFile(data)
			macroForPickle(self)
		if file_size > self.allocation_size:
			self.adapt_allocation_size(file_size)
		self.file_size = file_size

	def read(self, offset, length):
		startTime = time.time()
		if offset >= self.file_size:
			raise NTStatusEndOfFile()
		end_offset = min(self.file_size, offset + length)
		if not self.isCached:
			data = readFile(self.IDs)
			addToReadSpeed(len(data)/(time.time() - startTime))
			return data
		else:
			data = open(f"Cache\\{self.path.name.replace(backslash, '_')}", "rb").read()[offset:end_offset]
			self.cacheLastAccess = time.time()
			addToReadSpeed(len(data)/(time.time() - startTime))
			return data

	def write(self, buffer, offset, write_to_end_of_file):
		if write_to_end_of_file:
			offset = self.file_size
		end_offset = offset + len(buffer)
		if end_offset > self.file_size:
			self.set_file_size(end_offset)
		data = readFile(self.IDs)
		data[offset:end_offset] = buffer
		self.IDs = uploadFile(data)
		macroForPickle(self)
		return len(buffer)

	def constrained_write(self, buffer, offset):
		if offset >= self.file_size:
			return 0
		end_offset = min(self.file_size, offset + len(buffer))
		transferred_length = end_offset - offset
		data = readFile(self.IDs)
		data[offset:end_offset] = buffer[:transferred_length]
		self.IDs = uploadFile(data)
		macroForPickle(self)
		return transferred_length
	
class DiscordVirtualDisk(InMemoryFileSystemOperations):
	def __init__(self, sizeInGB = 16, read_only=False):
		super().__init__("")

		max_file_nodes = 1024
		max_file_size = sizeInGB * 1024 * 1024
		file_nodes = 0

		self._volume_info = {
			"total_size": max_file_nodes * max_file_size,
			"free_size": (max_file_nodes - file_nodes) * max_file_size,
			"volume_label": "Discord File System",
		}

		self.read_only = read_only
		self._root_path = PureWindowsPath("/")
		self._root_obj = FolderObj(
			self._root_path,
			FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
			SecurityDescriptor.from_string("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"),
		)
		self._entries = {self._root_path: self._root_obj}
		self._thread_lock = threading.Lock()
		self.webhookIndex = 0

	def _import_files(self, file_path):
		file_path = Path(file_path)
		path = self._root_path / file_path.name
		obj = DiscordFile(
			path,
			FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE,
			self._root_obj.security_descriptor,
		)
		self._entries[path] = obj
		obj.write(file_path.read_bytes(), 0, False)

	@operation
	def rename(self, file_context, file_name, new_file_name, replace_if_exists):
		if self.read_only:
			raise NTStatusMediaWriteProtected()
		file_name = PureWindowsPath(file_name)
		new_file_name = PureWindowsPath(new_file_name)
		try:
			file_obj = self._entries[file_name]
		except KeyError:
			raise NTStatusObjectNameNotFound()
		if new_file_name in self._entries:
			if new_file_name.name != self._entries[new_file_name].path.name:
				pass
			elif not replace_if_exists:
				raise NTStatusObjectNameCollision()
			elif not isinstance(file_obj, DiscordFile):
				raise NTStatusAccessDenied()
		for entry_path in list(self._entries):
			try:
				relative = entry_path.relative_to(file_name)
				new_entry_path = new_file_name / relative
				entry = self._entries.pop(entry_path)
				entry.path = new_entry_path
				self._entries[new_entry_path] = entry
			except ValueError:
				continue

	@operation
	def create(
		self,
		file_name,
		create_options,
		granted_access,
		file_attributes,
		security_descriptor,
		allocation_size,
	):
		if self.read_only:
			raise NTStatusMediaWriteProtected()
		file_name = PureWindowsPath(file_name)
		try:
			parent_file_obj = self._entries[file_name.parent]
			if isinstance(parent_file_obj, DiscordFile):
				raise NTStatusNotADirectory()
		except KeyError:
			raise NTStatusObjectNameNotFound()
		if file_name in self._entries:
			raise NTStatusObjectNameCollision()
		if create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE:
			file_obj = self._entries[file_name] = FolderObj(
				file_name, file_attributes, security_descriptor
			)
		else:
			file_obj = self._entries[file_name] = DiscordFile(
				file_name,
				file_attributes,
				security_descriptor,
				allocation_size,
			)
		return OpenedObj(file_obj)

	@operation
	def read_directory(self, file_context, marker):
		entries = []
		file_obj = file_context.file_obj
		if isinstance(file_obj, DiscordFile):
			raise NTStatusNotADirectory()
		if file_obj.path != self._root_path:
			parent_obj = self._entries[file_obj.path.parent]
			entries.append({"file_name": ".", **file_obj.get_file_info()})
			entries.append({"file_name": "..", **parent_obj.get_file_info()})
		for entry_path, entry_obj in self._entries.items():
			try:
				relative = entry_path.relative_to(file_obj.path)
			except ValueError:
				continue
			if len(relative.parts) != 1:
				continue
			entries.append({"file_name": entry_path.name, **entry_obj.get_file_info()})
		entries = sorted(entries, key=lambda x: x["file_name"])
		if marker is None:
			return entries
		for i, entry in enumerate(entries):
			if entry["file_name"] == marker:
				return entries[i + 1 :]

	@operation
	def cleanup(self, file_context, file_name, flags) -> None:
		if self.read_only:
			raise NTStatusMediaWriteProtected()
		FspCleanupDelete = 0x01
		FspCleanupSetAllocationSize = 0x02
		FspCleanupSetArchiveBit = 0x10
		FspCleanupSetLastAccessTime = 0x20
		FspCleanupSetLastWriteTime = 0x40
		FspCleanupSetChangeTime = 0x80
		file_obj = file_context.file_obj
		if flags & FspCleanupDelete:
			if any(key.parent == file_obj.path for key in self._entries):
				return
			try:
				del self._entries[file_obj.path]
			except KeyError:
				raise NTStatusObjectNameNotFound()
		if flags & FspCleanupSetAllocationSize:
			file_obj.adapt_allocation_size(file_obj.file_size)
		if flags & FspCleanupSetArchiveBit and isinstance(file_obj, DiscordFile):
			file_obj.attributes |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE
		if flags & FspCleanupSetLastAccessTime:
			file_obj.last_access_time = filetime_now()
		if flags & FspCleanupSetLastWriteTime:
			file_obj.last_write_time = filetime_now()
		if flags & FspCleanupSetChangeTime:
			file_obj.change_time = filetime_now()

def runVirtualDisk():
	testing = False
	debug = False
	if debug:
		enable_debug_log()
	mountpoint = Path("X:")
	is_drive = mountpoint.parent == mountpoint
	reject_irp_prior_to_transact0 = not is_drive and not testing
	global printCurrentReadSpeed
	global printCurrentWriteSpeed
	fs = FileSystem(
		str(mountpoint),
		DiscordVirtualDisk(1024*1024*1024),
		sector_size=512,
		sectors_per_allocation_unit=1,
		volume_creation_time=filetime_now(),
		volume_serial_number=0,
		file_info_timeout=1000,
		case_sensitive_search=1,
		case_preserved_names=1,
		unicode_on_disk=1,
		persistent_acls=1,
		post_cleanup_when_modified_only=1,
		um_file_context_is_user_context2=1,
		file_system_name=str(mountpoint),
		prefix="",
		debug=debug,
		reject_irp_prior_to_transact0=reject_irp_prior_to_transact0,
	)
	try:
		print("Starting File System...")
		fs.start()
		print("Started File System")
		startTime = time.time()
		while True:
			if printCurrentReadSpeed == True and printCurrentWriteSpeed == True:
				print(f"Timestamp {round(time.time()-startTime)} speeds: - - - {round(currentReadSpeed/1_024, 1)} KiB/s reads - - - - - - - {round(currentWriteSpeed/1_024, 1)} KiB/s writes")
				printCurrentReadSpeed = False
				printCurrentWriteSpeed = False
			elif printCurrentReadSpeed == True:
				print(f"Timestamp {round(time.time()-startTime)} speeds: - - - {round(currentReadSpeed/1_024, 1)} KiB/s reads")
				printCurrentReadSpeed = False
			elif printCurrentWriteSpeed == True:
				print(f"Timestamp {round(time.time()-startTime)} speeds: - - - {round(currentWriteSpeed/1_024, 1)} KiB/s writes")
				printCurrentWriteSpeed = False
			time.sleep(1)
	except KeyboardInterrupt:
		print("Stoping File System...")
		fs.stop()
		print("Stopped File System")

@client.event
async def on_ready():
	global channel
	channel = client.get_channel(CHANNEL_ID)
	print(f"{client.user} has connected to Discord.")
	threading.Thread(target=runVirtualDisk).start()

asyncio.run(client.run(TOKEN))
