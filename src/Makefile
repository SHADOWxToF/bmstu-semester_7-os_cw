# Указываем объектный файл для модуля
TARGET := finder
OBJS := main.o list.o
obj-m += $(TARGET).o
$(TARGET)-objs := $(OBJS)

# Получаем путь к исходникам ядра Linux из переменной окружения KDIR или используем значение по умолчанию
KDIR ?= /lib/modules/$(shell uname -r)/build

# Флаги
ccflags-y += -std=gnu18 -Wall

# Правило для сборки модуля
all:
	make -C $(KDIR) M=$(shell pwd) modules

$(TARGET).o: $(OBJS)
	$(LD) -r -o $@ $(OBJS)

reader:
	gcc -o reader.out reader.c

# Правило для очистки директории от лишних файлов
clean:
	make -C $(KDIR) M=$(shell pwd) clean
