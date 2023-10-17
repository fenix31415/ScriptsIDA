struct Setting__VFTable
{
  void * (__fastcall *dtor_0)(void *setting, char a2);
  bool (__fastcall *Func1_8)(void* setting);
};

struct SettingT_bool_
{
  Setting__VFTable *vftable;
  bool value;
	char pad_9[7];
  char *name;
};

struct SettingT_float_
{
  Setting__VFTable *vftable;
  float value;
	char pad_C[4];
  char *name;
};

struct SettingT_int_
{
  Setting__VFTable *vftable;
  int32 value;
	char pad_C[4];
  char *name;
};

struct SettingT_uint_
{
  Setting__VFTable *vftable;
  uint32 value;
	char pad_C[4];
  char *name;
};

struct SettingT_string_
{
  Setting__VFTable *vftable;
  char* value;
  char *name;
};

struct GameSettingCollection;

struct GameSettingCollection__VFTable
{
  void *(__fastcall *dtor_0)(GameSettingCollection *_this, char a2);
  void (__fastcall *InsertSetting_8)(GameSettingCollection* _this, void* setting);
  void (__fastcall *RemoveSetting_10)(GameSettingCollection* _this, void* setting);
  bool (__fastcall *WriteSetting_18)(GameSettingCollection* _this, void* setting);
  bool (__fastcall *ReadSetting_20)(GameSettingCollection* _this, void* setting);
  bool (__fastcall *OpenHandle_28)(GameSettingCollection* _this, bool a_create);
  bool (__fastcall *CloseHandle_30)(GameSettingCollection* _this);
  char (__fastcall *Func7_38)(GameSettingCollection* _this);
  void (__fastcall *WriteAllSettings)(GameSettingCollection* _this);
  void (__fastcall *ReadAllSettings)(GameSettingCollection* _this);
  int64 (__fastcall *Func10_50)(GameSettingCollection *_this, int64 a2, int64 a3);
};

struct GameSettingCollection
{
  GameSettingCollection__VFTable *vftable;
  char  subKey[0x104];
  char _pad_10[4];
  void *Handle_110;
  BSTCaseInsensitiveStringMap_Setting__ Settings_118;
};


struct INIPrefSettingCollection;

struct INIPrefSettingCollection__VFTable
{
  void *(__fastcall *dtor_0)(INIPrefSettingCollection *_this, char a2);
  void (__fastcall *InsertSetting_8)(INIPrefSettingCollection* _this, void* setting);
  void (__fastcall *RemoveSetting_10)(INIPrefSettingCollection* _this, void* setting);
  bool (__fastcall *WriteSetting_18)(INIPrefSettingCollection* _this, void* setting);
  bool (__fastcall *ReadSetting_20)(INIPrefSettingCollection* _this, void* setting);
  bool (__fastcall *OpenHandle_28)(INIPrefSettingCollection* _this, bool a_create);
  bool (__fastcall *CloseHandle_30)(INIPrefSettingCollection* _this);
  char (__fastcall *Func7_38)(INIPrefSettingCollection*);
  void (__fastcall *WriteAllSettings)(INIPrefSettingCollection* _this);
  void (__fastcall *ReadAllSettings)(INIPrefSettingCollection* _this);
};

struct INIPrefSettingCollection
{
  INIPrefSettingCollection__VFTable *vftable;
  char  subKey[0x104];
  char _pad_10[4];
  void *Handle_110;
  BSSimpleList_Setting__ Settings_118;
};

struct INISettingCollection;

struct INISettingCollection__VFTable
{
  void *(__fastcall *dtor_0)(INISettingCollection *_this, char a2);
  void (__fastcall *InsertSetting_8)(INISettingCollection* _this, void* setting);
  void (__fastcall *RemoveSetting_10)(INISettingCollection* _this, void* setting);
  bool (__fastcall *WriteSetting_18)(INISettingCollection* _this, void* setting);
  bool (__fastcall *ReadSetting_20)(INISettingCollection* _this, void* setting);
  bool (__fastcall *OpenHandle_28)(INISettingCollection* _this, bool a_create);
  bool (__fastcall *CloseHandle_30)(INISettingCollection* _this);
  char (__fastcall *Func7_38)(INISettingCollection*);
  void (__fastcall *WriteAllSettings)(INISettingCollection* _this);
  void (__fastcall *ReadAllSettings)(INISettingCollection* _this);
};

struct INISettingCollection
{
  INISettingCollection__VFTable *vftable;
  char  subKey[0x104];
  char _pad_10[4];
  void *Handle_110;
  BSSimpleList_Setting__ Settings_118;
};

struct RegSettingCollection;

struct RegSettingCollection__VFTable
{
  void *(__fastcall *dtor_0)(RegSettingCollection *_this, char a2);
  void (__fastcall *InsertSetting_8)(RegSettingCollection* _this, void* setting);
  void (__fastcall *RemoveSetting_10)(RegSettingCollection* _this, void* setting);
  bool (__fastcall *WriteSetting_18)(RegSettingCollection* _this, void* setting);
  bool (__fastcall *ReadSetting_20)(RegSettingCollection* _this, void* setting);
  bool (__fastcall *OpenHandle_28)(RegSettingCollection* _this, bool a_create);
  bool (__fastcall *CloseHandle_30)(RegSettingCollection* _this);
  char (__fastcall *Func7_38)(RegSettingCollection*);
  void (__fastcall *WriteAllSettings)(RegSettingCollection* _this);
  void (__fastcall *ReadAllSettings)(RegSettingCollection* _this);
};

struct RegSettingCollection
{
  RegSettingCollection__VFTable *vftable_RegSettingCollection_0;
  char  subKey[0x104];
  char _pad_10[4];
  void *Handle_110;
  BSSimpleList_Setting__ Settings_118;
};
